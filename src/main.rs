/*
 * Welcome to the world of a point proven.
 * The point being proven?
 * You cannot, reasonably, rewrite Doas in Rust, and if you manage to, it will just not be as good as the original.
 * Languages are not memory safe, good code is. And no language will save you from logic errors.
 * This is the real reason rustaceans are rewriting Sudo and not Doas. Because Doas is superior.
 * That being said, if you want a rusty Sudo replacement, please do consider forking this program and improving upon it. If it looks like the work of a C++ programmer banging his head on the desk at the weird rules of the silly crab language, that's because it is.
 * TODO: Refactor so the code looks less smooth-brained. 376K with size optimizations enabled? On your bike! I need to get it smaller.
 */

use std::{env, ffi::CString, fs::read_to_string, io, path::Path, process::ExitCode};
use core::ops::BitOrAssign;
use nix::syslog::{syslog, Facility, Severity, Priority};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{setuid, setgid, execvp, fork, ForkResult, User, Group, Gid, getgrouplist, getuid, gethostname, getcwd};
use pam::{client::Client, PamResult, PamError};
mod timestamp;

enum DoasOpt {
    Persist,
    Nopass,
    Setenv,
    Keepenv,
    Nolog,
}

enum Action{
    Permit,
    Deny,
}

struct DoasRule {
    action: Action,
    options: Vec<DoasOpt>,
    user: Option<String>,
    group: Option<String>,
    as_user: Option<String>,
    cmd: Option<String>,
    setenv: Vec<String>,
}

struct Permissions {
    permit: bool,
    permit_group: bool,
    deny: bool,
    deny_group: bool,
    nolog: bool,
}

impl Permissions {
    pub fn new() -> Self {
        Permissions{
            permit: false,
            permit_group: false,
            deny: false,
            deny_group: false,
            nolog: false,
        }
    }
}



impl BitOrAssign for Permissions{
    fn bitor_assign(&mut self, rhs: Self) {
        self.permit |= rhs.permit;
        self.permit_group |= rhs.permit_group;
        self.deny |= rhs.deny;
        self.deny_group |= rhs.deny_group;
        self.nolog |= rhs.nolog;
    }
}

fn get_groups(user: &User) -> Vec<Gid>{
    let username = CString::new(user.name.clone()).unwrap();
    let groups = getgrouplist(&username, user.gid).unwrap();
    groups
}

fn is_in_group(user: &User, group_name: &str) -> bool {
    let group = Group::from_name(group_name).unwrap().unwrap();
    let user_groups = get_groups(user);
    user_groups.contains(&group.gid)
}

fn pam_result_to_io<T>(err: PamResult<T>) -> io::Result<T>{
    err.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("PAM error: {}", e)))
}

fn parse_config<P: AsRef<Path>>(config_path: P) -> Vec<DoasRule> {
    let content = read_to_string(config_path).expect("Failed to read doas.conf");
    let mut rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let action_token = tokens.next();
        let action = match action_token.unwrap() {
            "permit" => Action::Permit,
            "deny" => Action::Deny,
            _ => continue,
        };
        let mut options = Vec::new();
        let mut user = None;
        let mut group = None;
        let mut as_user = None;
        let mut cmd = None;
        let mut setenv = Vec::<String>::new();
        let mut is_setenv = false;
        while let Some(token) = tokens.next() {
            match token {
                tok if is_setenv => {
                    if tok == "}" {
                        is_setenv = false;
                        continue;
                    }
                    if tok.ends_with("}") {
                        is_setenv = false;
                        setenv.push(tok.trim_end_matches("}").to_string());
                        continue;
                    }
                    setenv.push(tok.to_string());
                }
                "{" => {
                    is_setenv = true;
                }
                "as" => {
                    as_user = tokens.next().map(String::from);
                }
                "cmd" => {
                    cmd = tokens.next().map(String::from);
                }
                tok if tok == "persist" || tok == "nopass" || tok == "keepenv" || tok == "nolog" || tok == "setenv" => {
                    options.push(match tok {
                        "persist" => DoasOpt::Persist,
                        "nopass" => DoasOpt::Nopass,
                        "keepenv" => DoasOpt::Keepenv,
                        "nolog" => DoasOpt::Nolog,
                        "setenv" => DoasOpt::Setenv,
                        _ => continue,
                    });
                }
                tok if tok == "setenv{" => {
                    options.push(DoasOpt::Setenv);
                    is_setenv = true;
                    continue;
                }
                tok if tok.starts_with("setenv{") => {
                    options.push(DoasOpt::Setenv);
                    is_setenv = true;
                    setenv.push(tok.split_once("{").unwrap().1.to_string());
                }
                tok if tok.starts_with(':') => {
                    if group.is_none() {
                        group = Some(tok.trim_start_matches(':').to_string());
                    }
                }
                tok => {
                    if user.is_none() {
                        user = Some(tok.to_string());
                    }
                }
            }
        }
        rules.push(DoasRule {
            action,
            options,
            user,
            group,
            as_user,
            cmd,
            setenv,
        });

    }
    rules
}

fn authenticate_user(username: &str, password: &str) -> Result<bool, PamError> {
    let mut auth = Client::with_password("doas")?;
    auth.conversation_mut().set_credentials(username, password);
    return match auth.authenticate() {
        Ok(()) => Ok::<bool, PamError>(true),
        Err(_e) => Ok::<bool, PamError>(false),
    };

}
fn run_command_as_user(user: &str, command: &[String], keepenv: bool, username: &String, setenv: bool, envrules: Vec<(String, String)>) -> io::Result<i32> {
    let pwd = User::from_name(user).unwrap().unwrap();
    let uid = pwd.uid;
    let gid = pwd.gid;
    let safe_path = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin".to_string();
    let mut newvars: Vec<(String, String)> = Vec::<(String, String)>::new();
    newvars.push(("DOAS_USER".to_string(), username.to_owned()));
    for var in env::vars(){
        match var.0.as_str() {
            "DISPLAY" => newvars.push(var),
            "TERM" => newvars.push(var),
            _ => continue,
        }
        newvars.push(("USER".to_string(), user.to_string()));
        newvars.push(("LOGNAME".to_string(), user.to_string()));
        newvars.push(("HOME".to_string(), pwd.dir.to_string_lossy().into_owned()));
        newvars.push(("SHELL".to_string(), pwd.shell.to_string_lossy().into_owned()));
        newvars.push(("PATH".to_string(), safe_path.clone()));
    }
    if setenv {
        for rule in envrules{
            newvars.push(rule);
        }
    }

    // Can I find a way to do this without unsafe? Only time will tell.
    // Spoilers: Probably not. Rust's idea of safe restricts both safe and unsafe code and creates bloat.
    match unsafe { fork() }? {
        ForkResult::Child => {
            setgid(gid).expect("Failed to setgid");
            setuid(uid).expect("Failed to setuid");
            if !keepenv {
                for var in env::vars(){ // Removed a match condition I ended up not using
                    unsafe {env::remove_var(var.0)};
                }
            }
            for var in newvars{
                unsafe {env::set_var(var.0, var.1)};
            }
            let c_args: Vec<CString> = command
                .iter()
                .map(|s| CString::new(s.as_bytes()).unwrap())
                .collect();
            let c_command = c_args[0].clone();

            let _ = execvp(&c_command, &c_args);
            let err = Err(io::Error::last_os_error());
            match err {
                Ok(err) => Ok(err),
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::NotFound => {
                            eprintln!("doas: {}: command not found", c_command.to_string_lossy());
                            return Ok(1);
                        },
                        _ => {
                            return Err(err);
                        }
                    }
                }
            }
        }
        ForkResult::Parent { child } => {
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Command killed by signal: {:?}", sig),
                )),
                status => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Unexpected wait status: {:?}", status),
                )),
            }
        }
    }
}

fn main() -> ExitCode {
    let cwd_binding = getcwd().unwrap();
    let cwd = cwd_binding.to_str().unwrap();
    let hostname_binding =  gethostname().expect("Failed getting hostname");
    let hostname = hostname_binding.to_str();
    let args: Vec<String> = env::args().collect();
    let mut target_user = "root".to_string();
    let mut argindex = 0;
    let mut nonint = false;
    let mut shell = false;
    let mut userset = false;
    let tgtshell: String;
    let mut command: &[String] = &["".to_string()];
    let mut help = false;
    let mut command_start_index = 1;
    for arg in &args{
        argindex += 1;
        if arg.starts_with("-") && argindex < 4{
            if userset{
                eprintln!("No switches allowed after -u");
            }
            match arg{
                _ if arg.contains("h") => help = true,
                _ if arg.contains("L") => {
                    timestamp::timestamp_clear();
                    return ExitCode::from(0);
                }
                _ if arg.contains("n") => nonint = true,
                _ if arg.contains("s") => shell = true,
                _ if arg.contains("u") => {
                    target_user = args[argindex].clone();
                    userset = true;
                }
                _ => continue,
            }
            match userset {
                false => command_start_index = argindex,
                true => command_start_index = argindex + 1,
            }
        }
    }
    if args.len() < 2 || help{
        eprintln!("Usage: {} [-Lns] [-u user] <command> [arguments...]", args[0]);
        eprintln!("Do not use in production! Not all features of doas are implemented, many may be insecure.");
        return ExitCode::from(1);
    }
    if !shell {
        command = &args[command_start_index..];
    }
    let config = parse_config("/etc/doas.conf");
    let runuser = User::from_uid(getuid()).unwrap().unwrap();
    let username = &runuser.name;
    let mut persist = false;
    let mut need_pass = true;
    let mut keepenv = false;
    let mut setenv = false;
    let mut envrules = Vec::<(String, String)>::new();
    let mut perms = Permissions::new();
    for rule in config{
        let mut this_perms = Permissions::new();

        let matches_user = match &rule.user{
            Some(rule_user) => rule_user == username,
            None => false,
        };
        if matches_user{
            match rule.action{
                Action::Permit => this_perms.permit = true,
                Action::Deny => this_perms.deny = true,
            }
        }
        let matches_group = match &rule.group{
            Some(rule_group) => is_in_group(&runuser, rule_group),
            None => false,
        };
        if matches_group{
            match &rule.action{
                Action::Permit => this_perms.permit_group = true,
                Action::Deny => this_perms.deny_group = true,
            };
        }
        if matches_user || matches_group{
            if rule.cmd != None{
                // Rudimentary support for cmd rule
                if rule.cmd.unwrap() != command[0] { continue }
            }
            if rule.as_user != None {
                // Rudimentary support for as rule
                if rule.as_user.unwrap() != target_user{ continue }
            }
            if !(this_perms.deny || this_perms.deny_group){
                for op in rule.options{
                    match op{
                        DoasOpt::Nopass => need_pass = false,
                        DoasOpt::Persist => persist = true,
                        DoasOpt::Nolog => this_perms.nolog = true,
                        DoasOpt::Keepenv => keepenv = true,
                        DoasOpt::Setenv => setenv = true,
                    };
                }
            }
            if !rule.setenv.is_empty(){
                for set in rule.setenv{
                    if !set.contains("="){
                        eprintln!("Keepenv rules in setenv not yet implemented");
                        continue;
                    }
                    let setvec = set.split_once("=").unwrap();
                    envrules.push((setvec.0.to_string(),setvec.1.to_string()));
                }
            }
        }
        perms |= this_perms;
    };
    if shell{
        tgtshell = User::from_name(&target_user).unwrap().unwrap().shell.to_string_lossy().into_owned();
        command = std::array::from_ref(&tgtshell);
    }
    if (perms.permit == false && perms.permit_group == false) || perms.deny == true || perms.deny_group == true {
        eprintln!("Permission denied");
        if !perms.nolog {
            let priority = Priority::new(Severity::LOG_NOTICE, Facility::LOG_AUTH);
            syslog(priority, &format!("command not permitted for {}: {}", &username, command.join(" "))).unwrap();
        }
        return ExitCode::from(1);
    }
    if persist && need_pass {
        need_pass = !timestamp::timestamp_check(5 * 60);
    }
    if need_pass == true {
        //TODO: Try to eliminate this dependency.
        let password = rpassword::prompt_password(format!("doas ({}@{}) password: ", username, hostname.unwrap())).expect("Failed to read password");
        if nonint{
            eprintln!("Non-interactive but user needs to enter a password");
            return ExitCode::from(1);
        }

        if !pam_result_to_io(authenticate_user(&username, &password)).unwrap() {
            eprintln!("Authentication failed");
            return ExitCode::from(1);
        }
    }
    if persist {
        timestamp::timestamp_set();
    }
    if !perms.nolog {
        let priority = Priority::new(Severity::LOG_INFO, Facility::LOG_AUTH);
        syslog(priority, &format!("{} ran command {} as {} in {}", &username, command.join(" "), &target_user, cwd)).unwrap();
    }
    /* The return-expect method causes a panic if the child process dies uncleanly.
     * The print-return method prints the error message normally, but crashing a child process like nano will leave the terminal unable to echo stdin.
     * Comment one and uncomment the other to test them.*/

    return ExitCode::from(run_command_as_user(&target_user, command, keepenv, username, setenv, envrules).expect("") as u8);
    /*let res = run_command_as_user(&target_user, command, keepenv, username, setenv, envrules);
    match res {
        Ok(err) => {
            return ExitCode::from(err as u8);
        }
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::from(1);
        }
    }*/
}
