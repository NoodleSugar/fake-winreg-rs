// Copyright 2023, Igor Shaula
// Licensed under the MIT License <LICENSE or
// http://opensource.org/licenses/MIT>. This file
// may not be copied, modified, or distributed
// except according to those terms.
use crate::enums::*;
use crate::reg_value::RegValue;
use crate::types::{FromRegValue, ToRegValue};
use std::collections::HashMap;
use std::default::Default;
use std::ffi::OsStr;
use std::io::{self, Error};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
pub use windows_sys::Win32::System::Registry::HKEY;

/// Handle of opened registry key
#[derive(Debug, Clone)]
pub struct RegKey {
    value: RegValue,
    children: HashMap<String, Self>,
}

impl RegKey {
    pub fn predef(hkey: HKEY) {
        let key = match hkey {
            HKEY_CLASSES_ROOT => "HKEY_CLASSES_ROOT",
            HKEY_CURRENT_CONFIG => "HKEY_CURRENT_CONFIG",
            HKEY_CURRENT_USER => "HKEY_CURRENT_USER",
            HKEY_CURRENT_USER_LOCAL_SETTINGS => "HKEY_CURRENT_USER_LOCAL_SETTINGS",
            HKEY_DYN_DATA => "HKEY_DYN_DATA",
            HKEY_LOCAL_MACHINE => "HKEY_LOCAL_MACHINE",
            HKEY_PERFORMANCE_DATA => "HKEY_PERFORMANCE_DATA",
            HKEY_PERFORMANCE_NLSTEXT => "HKEY_PERFORMANCE_NLSTEXT",
            HKEY_PERFORMANCE_TEXT => "HKEY_PERFORMANCE_TEXT",
            HKEY_USERS => "HKEY_USERS",
            _ => "",
        };

        let storage = Self::global_storage();
        storage.lock().unwrap().children.get_mut(key).unwrap();
    }

    pub fn global_storage() -> &'static Mutex<Self> {
        static REG_STORAGE: OnceLock<Mutex<RegKey>> = OnceLock::new();
        REG_STORAGE.get_or_init(|| Mutex::new(Self::miniminimal_windows_testregistry()))
    }

    pub fn miniminimal_windows_testregistry() -> Self {
        let mut reg_key = Self::new();

        let data = vec![
            (
                PathBuf::from_iter([
                    "HKEY_LOCAL_MACHINE",
                    "SOFTWARE",
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "CurrentBuild",
                ]),
                RegValue {
                    bytes: "18363".into(),
                    vtype: REG_SZ,
                },
            ),
            (
                PathBuf::from_iter([
                    "HKEY_LOCAL_MACHINE",
                    "SOFTWARE",
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "ProfileList",
                    "S-1-5-18",
                    "ProfileImagePath",
                ]),
                RegValue {
                    bytes: r"%systemroot%\system32\config\systemprofile".into(),
                    vtype: REG_EXPAND_SZ,
                },
            ),
            (
                PathBuf::from_iter([
                    "HKEY_LOCAL_MACHINE",
                    "SOFTWARE",
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "ProfileList",
                    "S-1-5-19",
                    "ProfileImagePath",
                ]),
                RegValue {
                    bytes: r"%systemroot%\ServiceProfiles\LocalService".into(),
                    vtype: REG_EXPAND_SZ,
                },
            ),
            (
                PathBuf::from_iter([
                    "HKEY_LOCAL_MACHINE",
                    "SOFTWARE",
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "ProfileList",
                    "S-1-5-20",
                    "ProfileImagePath",
                ]),
                RegValue {
                    bytes: r"%systemroot%\ServiceProfiles\NetworkService".into(),
                    vtype: REG_EXPAND_SZ,
                },
            ),
            (
                PathBuf::from_iter([
                    "HKEY_LOCAL_MACHINE",
                    "SOFTWARE",
                    "Microsoft",
                    "Windows NT",
                    "CurrentVersion",
                    "ProfileList",
                    "S-1-5-21-206651429-2786145735-121611483-1001",
                    "ProfileImagePath",
                ]),
                RegValue {
                    bytes: r"C:\Users\bitranox".into(),
                    vtype: REG_EXPAND_SZ,
                },
            ),
            (
                PathBuf::from_iter([
                    "HKEY_USERS",
                    "S-1-5-21-206651429-2786145735-121611483-1001",
                    "Volatile Environment",
                    "USERNAME",
                ]),
                RegValue {
                    bytes: "bitranox".into(),
                    vtype: REG_SZ,
                },
            ),
        ];

        for (subkey_path, subkey_value) in data {
            let (key, _) = reg_key.create_subkey(subkey_path.clone()).unwrap();
            key.set_raw_value("", &subkey_value).unwrap();
        }

        reg_key
            .create_subkey(PathBuf::from_iter(["HKEY_USERS", ".DEFAULT"]))
            .unwrap();
        reg_key
            .create_subkey(PathBuf::from_iter(["HKEY_USERS", "S-1-5-18"]))
            .unwrap();
        reg_key
            .create_subkey(PathBuf::from_iter(["HKEY_USERS", "S-1-5-19"]))
            .unwrap();
        reg_key
            .create_subkey(PathBuf::from_iter(["HKEY_USERS", "S-1-5-20"]))
            .unwrap();
        reg_key
            .create_subkey(PathBuf::from_iter([
                "HKEY_USERS",
                "S-1-5-21-206651429-2786145735-121611483-1001",
            ]))
            .unwrap();
        reg_key
            .create_subkey(PathBuf::from_iter([
                "HKEY_USERS",
                "S-1-5-21-206651429-2786145735-121611483-1001_Classes",
            ]))
            .unwrap();

        reg_key
    }

    pub fn new() -> Self {
        Self {
            value: RegValue::default(),
            children: HashMap::default(),
        }
    }

    pub fn open_subkey<P: AsRef<OsStr>>(&mut self, path: P) -> io::Result<&mut Self> {
        let path: &Path = path.as_ref().as_ref();

        let mut subkey = self;
        for path_comp in path.iter() {
            let path_comp = path_comp.to_str().unwrap();

            subkey = match subkey.children.get_mut(path_comp) {
                Some(child) => child,
                None => {
                    let message = format!("Subkey {path:?} not found");
                    return Err(Error::new(io::ErrorKind::NotFound, message));
                }
            };
        }

        Ok(subkey)
    }

    pub fn create_subkey<P: AsRef<OsStr>>(
        &mut self,
        path: P,
    ) -> io::Result<(&mut Self, RegDisposition)> {
        let path: &Path = path.as_ref().as_ref();

        let mut subkey = self;
        let mut dispo = RegDisposition::REG_OPENED_EXISTING_KEY;
        for path_comp in path.iter() {
            let path_comp = path_comp.to_str().unwrap();

            if !subkey.children.contains_key(path_comp) {
                dispo = RegDisposition::REG_CREATED_NEW_KEY;
                subkey.children.insert(path_comp.to_string(), Self::new());
            }

            subkey = subkey.children.get_mut(path_comp).unwrap();
        }

        Ok((subkey, dispo))
    }

    pub fn get_value<T: FromRegValue, N: AsRef<OsStr>>(&mut self, name: N) -> io::Result<T> {
        match self.get_raw_value(name) {
            Ok(ref val) => FromRegValue::from_reg_value(val),
            Err(err) => Err(err),
        }
    }

    pub fn get_raw_value<N: AsRef<OsStr>>(&mut self, name: N) -> io::Result<RegValue> {
        self.open_subkey(name).map(|k| k.value.clone())
    }

    pub fn set_value<T: ToRegValue, N: AsRef<OsStr>>(
        &mut self,
        name: N,
        value: &T,
    ) -> io::Result<()> {
        self.set_raw_value(name, &value.to_reg_value())
    }

    pub fn set_raw_value<N: AsRef<OsStr>>(&mut self, name: N, value: &RegValue) -> io::Result<()> {
        let key = self.open_subkey(name)?;
        key.value = value.clone();

        Ok(())
    }
}
