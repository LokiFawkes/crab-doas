	use nix::unistd::{getppid, getsid, getuid, Pid, unlink};
	use nix::time::{clock_gettime, ClockId};
	use std::io::{Read, Write};
	use std::{fs, fs::File, path::Path, fs::Permissions, fs::create_dir};
	use std::os::unix::fs::{PermissionsExt, chown, MetadataExt};

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
		let mut file = File::create(path).unwrap();
		let boottime = clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap();
		let realtime = clock_gettime(ClockId::CLOCK_REALTIME).unwrap();
		file.set_permissions(perms).unwrap();
		chown(path, Some(0), Some(0)).unwrap();
		file.write(format!("{} {}", boottime.tv_sec(), realtime.tv_sec()).as_bytes()).unwrap();
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
		let mut file = File::open(path).unwrap();
		let boottime = clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap();
		let realtime = clock_gettime(ClockId::CLOCK_REALTIME).unwrap();
		let meta = file.metadata().unwrap();
		let mut contents = String::new();
		file.read_to_string(&mut contents).unwrap();
		let parts = contents.split(" ").collect::<Vec<&str>>();
		if parts.len() < 2{
			eprintln!("Invalid timestamp");
			unlink(path).unwrap();
			return false;
		}
		let boottimestamp = parts[0].parse::<u64>().unwrap();
		let realtimestamp = parts[1].parse::<u64>().unwrap();
		if meta.permissions().mode() & 0o777 != 0o000 || meta.uid() != 0 || meta.gid() != 0 {
			eprintln!("Timestamp permissions compromised. Timestamp deleted.");
			chown(path.parent().unwrap(), Some(0), Some(0)).unwrap();
			unlink(path).unwrap();
			return false;
		}
		if boottimestamp < boottime.tv_sec().cast_unsigned() - secs || realtimestamp < realtime.tv_sec().cast_unsigned() - secs{
			unlink(path).unwrap();
			return false;
		}
		if boottimestamp > boottime.tv_sec().cast_unsigned() + 1 || realtimestamp > realtime.tv_sec().cast_unsigned() + 1{
			unlink(path).unwrap();
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
