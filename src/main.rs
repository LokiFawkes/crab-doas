/*
 * Welcome to the world of a point proven.
 * The point being proven?
 * You cannot, reasonably, rewrite Doas in Rust, and if you manage to, it will just not be as good as the original.
 * Languages are not memory safe, good code is. And no language will save you from logic errors.
 * This is the real reason rustaceans are rewriting Sudo and not Doas. Because Doas is superior.
 * That being said, if you want a rusty Sudo replacement, please do consider forking this program and improving upon it. I can't be arsed with this syntax. If it looks like the work of a C++ programmer banging his head on the desk at the weird rules of the silly crab language, that's because it is.
 * I can certify this program is not vibe-coded. I cannot certify that the code I studied from across the internet is not vibe-coded. It's very likely that most Rust code in the world is vibe-coded.
 * In fact, I'm pretty sure an AI would have put a lot more unsafe blocks in this. nix::unistd is a godsend.
 * TODO: Refactor so the code looks less smooth-brained. 392K with size optimizations enabled? On your bike! I need to get it smaller.
 */

use std::{env, ffi::CString, fs::read_to_string, io, path::Path};
use nix::syslog::{syslog, Facility, Severity, Priority};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{setuid, setgid, execvp, fork, ForkResult, User, Group, Gid, getgrouplist, getuid, gethostname, getcwd};
use pam::{client::Client, PamResult, PamError};

enum Action{
    Permit,
    Deny,
}

struct DoasRule {
    action: Action,
    options: Vec<String>,
    user: Option<String>,
    group: Option<String>,
    as_user: Option<String>,
    cmd: Option<String>,
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
        while let Some(token) = tokens.next() {
            match token {
                "as" => {
                    as_user = tokens.next().map(String::from);
                }
                "cmd" => {
                    cmd = tokens.next().map(String::from);
                }
                tok if tok == "persist" || tok == "nopass" || tok == "keepenv" || tok == "nolog" => {
                    options.push(tok.to_string());
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
fn run_command_as_user(user: &str, command: &[String]) -> io::Result<i32> {
    let pwd = User::from_name(user).unwrap().unwrap();
    let uid = pwd.uid;
    let gid = pwd.gid;
    match unsafe { fork() }? {
        ForkResult::Child => {
            setgid(gid).expect("Failed to setgid");
            setuid(uid).expect("Failed to setuid");
            let c_args: Vec<CString> = command
                .iter()
                .map(|s| CString::new(s.as_bytes()).unwrap())
                .collect();
            let c_command = c_args[0].clone();

            execvp(&c_command, &c_args).expect("exec failed");
            Err(io::Error::last_os_error())
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

fn main() -> io::Result<()> {
    let cwd_binding = getcwd().unwrap();
    let cwd = cwd_binding.to_str().unwrap();
    let mut nolog = false;
    let hostname_binding =  gethostname().expect("Failed getting hostname");
    let hostname = hostname_binding.to_str();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} [-u user] <command> [arguments...]", args[0]);
        eprintln!("Do not use in production! Many features such as 'persist' are not implemented.");
        return Ok(());
    }
    let mut target_user = "root".to_string();
    let command_start_index;
    if args.len() >= 4 && &args[1] == "-u" {
        target_user = args[2].clone();
        command_start_index = 3;
    } else {
        command_start_index = 1;
    }
    let command = &args[command_start_index..];
    let config = parse_config("/etc/doas.conf");
    let runuser = User::from_uid(getuid()).unwrap().unwrap();
    let username = &runuser.name;
    let mut permit = false;
    let mut deny = false;
    let mut permit_group = false;
    let mut deny_group = false;
    let mut need_pass = true;
    for rule in config{
        // Local permit/deny mutables. Feels too pedestrian, but allows me to evaluate multiple matched rules more gracefully
        let mut this_permit = false;
        let mut this_deny = false;
        let mut this_permit_group = false;
        let mut this_deny_group = false;
        let mut this_nolog = false;

        let matches_user = match &rule.user{
            Some(rule_user) => rule_user == username,
            None => false,
        };
        if matches_user{
            match rule.action{
                Action::Permit => this_permit = true,
                Action::Deny => this_deny = true,
            };
        }
        let matches_group = match &rule.group{
            Some(rule_group) => is_in_group(&runuser, rule_group),
            None => false,
        };
        if matches_group{
            match &rule.action{
                Action::Permit => this_permit_group = true,
                Action::Deny => this_deny_group = true,
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
            if !(this_deny || this_deny_group){
                for op in rule.options{
                    match op.as_str() {
                        "nopass" => need_pass = false,
                        "persist" => eprintln!("Persist not yet implemented"),
                        "nolog" => this_nolog = true,
                        "keepenv" => eprintln!("Keepenv not yet implemented"),
                        "setenv" => eprintln!("Setenv not yet implemented"),
                        _ => (),
                    };
                }
            }
        }
        permit |= this_permit;
        permit_group |= this_permit_group;
        deny |= this_deny;
        deny_group |= this_deny_group;
        nolog |= this_nolog;
    };
    if (permit == false && permit_group == false) || deny == true || deny_group == true {
        eprintln!("Permission denied");
        if !nolog {
            let priority = Priority::new(Severity::LOG_NOTICE, Facility::LOG_AUTH);
            syslog(priority, &format!("command not permitted for {}: {}", &username, command.join(" "))).unwrap();
        }
        return Ok(());
    }
    if need_pass == true {
        //TODO: Research nix unistd further, to eliminate rpassword dependency
        let password = rpassword::prompt_password(format!("doas ({}@{}) password:", username, hostname.unwrap())).expect("Failed to read password");
        if !pam_result_to_io(authenticate_user(&username, &password))? {
            eprintln!("Authentication failed");
            return Ok(());
        }
    }
    if !nolog {
        let priority = Priority::new(Severity::LOG_INFO, Facility::LOG_AUTH);
        syslog(priority, &format!("{} ran command {} as {} in {}", &username, command.join(" "), &target_user, cwd)).unwrap();
    }
    run_command_as_user(&target_user, command)?;
    Ok(())
}
