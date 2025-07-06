	use nix::unistd::{getppid, getsid, getuid, Pid, unlink};
	use std::{fs, fs::File, path::Path, fs::FileTimes, fs::Permissions, fs::create_dir};
	use std::os::unix::fs::{PermissionsExt, chown};
	use std::time::{SystemTime, Duration};

	pub struct Procinfo {
		ttynr: i32,
		starttime: u64,
	}

	const TIMESTAMP_DIR: &str = "/run/crab-doas";
	fn create_timestamp_path(){
		let path = Path::new(TIMESTAMP_DIR);
		create_dir(path).unwrap();
		let dirperms = <Permissions as PermissionsExt>::from_mode(0o600);
		fs::set_permissions(path, dirperms).unwrap();
		chown(path, Some(0), Some(0)).unwrap();
	}

	pub fn proc_info (pid: Pid) -> Procinfo{
		let path = format!("/proc/{}/stat", pid);
		let content : String = fs::read_to_string(&path).unwrap();
		let tokens = content.split(")").last().unwrap().trim().split_whitespace();
		let mut procinfo = Procinfo {
			ttynr: 0,
			starttime: 0,
		};
		let mut n = 2;
		for tok in tokens{
			n += 1;
			match n{
				7 => procinfo.ttynr = tok.parse::<i32>().unwrap(),
				22 => procinfo.starttime = tok.parse::<u64>().unwrap(),
				_ => continue,
			}
		}
		return procinfo;

	}

	pub fn timestamp_path () -> String {
		let ppid = getppid();
		let sid = getsid(Some(Pid::from_raw(0))).unwrap();
		let procinfo = proc_info(ppid);
		return format!("{}/{}-{}-{}-{}-{}", TIMESTAMP_DIR, ppid, sid, procinfo.ttynr, procinfo.starttime, getuid());
	}

	pub fn timestamp_set () {
		if !Path::new(TIMESTAMP_DIR).exists(){
			create_timestamp_path();
		}
		let tspath: &str = &timestamp_path();
		let path = Path::new(tspath);
		let perms = <Permissions as PermissionsExt>::from_mode(0o000);
		let file = File::create(path).unwrap();
		File::options().write(true).open(path).unwrap();
		let times: FileTimes = FileTimes::new();
		let systime = SystemTime::now();
		times.set_accessed(systime);
		times.set_modified(systime);
		file.set_times(times).unwrap();
		file.set_permissions(perms).unwrap();
	}

	pub fn timestamp_check (secs: u64) -> bool {
		if !Path::new(TIMESTAMP_DIR).exists(){
			create_timestamp_path();
		}
		let tspath: &str = &timestamp_path();
		let path = Path::new(tspath);
		if !path.exists(){
			return false;
		}
		let file = File::open(path).unwrap();
		let meta = file.metadata().unwrap();
		let atim = meta.accessed().unwrap();
		let mtim = meta.modified().unwrap();
		let systime = SystemTime::now();
		let timeout = Duration::from_secs(secs);
		/* OpenDoas sets atime to boot time (time since booting even counted while sleeping) but silly crab language doesn't like setting
		 * atime in the past and mtime in the future, and has this bad habit of not setting atime after birth, so I've lowered the scrutiny
		 * since both times are just SystemTime::now(). Could this make doas less secure? Maybe. Let's find out.*/
		if atim < systime - timeout && mtim < systime - timeout {
			unlink(path).unwrap();
			return false;
		}
		if atim > systime || mtim > systime {
			return false;
		}

		return true;
	}

	pub fn timestamp_clear (){
		if !Path::new(TIMESTAMP_DIR).exists(){
			create_timestamp_path();
		}
		let tspath: &str = &timestamp_path();
		let path = Path::new(tspath);
		if path.exists(){
			unlink(path).unwrap();
		}
	}
