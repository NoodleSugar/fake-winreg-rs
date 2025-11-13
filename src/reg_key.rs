// Copyright 2023, Igor Shaula
// Licensed under the MIT License <LICENSE or
// http://opensource.org/licenses/MIT>. This file
// may not be copied, modified, or distributed
// except according to those terms.
use crate::enums::*;
use crate::reg_value::RegValue;
use crate::types::ToRegValue;
use std::ffi::OsStr;
use std::io::Error;
use std::path::Path;
use windows_sys::Win32::System::Registry;
pub use windows_sys::Win32::System::Registry::HKEY;

/// Handle of opened registry key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKey {
    key: String,
    sub_keys: Vec<String>,
}

impl RegKey {
    pub fn predef(hkey: HKEY) -> std::io::Result<Self> {
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

        if !std::fs::exists(key)? {
            let file = std::fs::File::create(key)?;

            let data = match hkey {
                HKEY_LOCAL_MACHINE => hkey_local_machine_data(),
                HKEY_USERS => hkey_users_data(),
                _ => serde_json::json!({}),
            };
            serde_json::to_writer(file, &data)?;
        }

        Ok(RegKey {
            key: key.to_string(),
            sub_keys: Vec::new(),
        })
    }

    pub fn open_subkey_with_options_flags<P: AsRef<OsStr>>(
        &self,
        path: P,
        _options: Registry::REG_OPEN_CREATE_OPTIONS,
        _perms: Registry::REG_SAM_FLAGS,
    ) -> std::io::Result<RegKey> {
        self.open_subkey(path)
    }

    pub fn open_subkey_with_flags<P: AsRef<OsStr>>(
        &self,
        path: P,
        _perms: Registry::REG_SAM_FLAGS,
    ) -> std::io::Result<RegKey> {
        self.open_subkey(path)
    }

    pub fn open_subkey<P: AsRef<OsStr>>(&self, path: P) -> std::io::Result<Self> {
        let path: &Path = path.as_ref().as_ref();
        let path_keys: Vec<String> = path
            .iter()
            .map(OsStr::to_str)
            .map(Option::unwrap)
            .map(String::from)
            .collect();

        let reg_key = {
            let key = self.key.clone();
            let mut sub_keys = self.sub_keys.clone();
            sub_keys.append(&mut path_keys.clone());

            RegKey { key, sub_keys }
        };

        let mut storage = reg_key.load_storage()?;
        Self::storage_subkey(&mut storage, &reg_key.sub_keys)?;

        Ok(reg_key)
    }

    pub fn create_subkey_with_flags<P: AsRef<OsStr>>(
        &self,
        path: P,
        _perms: Registry::REG_SAM_FLAGS,
    ) -> std::io::Result<(RegKey, RegDisposition)> {
        self.create_subkey(path)
    }

    pub fn create_subkey_with_options_flags<P: AsRef<OsStr>>(
        &self,
        path: P,
        _options: Registry::REG_OPEN_CREATE_OPTIONS,
        _perms: Registry::REG_SAM_FLAGS,
    ) -> std::io::Result<(RegKey, RegDisposition)> {
        self.create_subkey(path)
    }

    pub fn create_subkey<P: AsRef<OsStr>>(
        &self,
        path: P,
    ) -> std::io::Result<(Self, RegDisposition)> {
        let path: &Path = path.as_ref().as_ref();
        let path_keys: Vec<String> = path
            .iter()
            .map(OsStr::to_str)
            .map(Option::unwrap)
            .map(String::from)
            .collect();

        let mut dispo = RegDisposition::REG_OPENED_EXISTING_KEY;
        let reg_key = {
            let key = self.key.clone();
            let mut sub_keys = self.sub_keys.clone();
            sub_keys.append(&mut path_keys.clone());

            RegKey { key, sub_keys }
        };

        let mut storage = self.load_storage()?;
        let mut json_value = &mut storage;
        for sub_key in &reg_key.sub_keys {
            if !json_value.contains_key(sub_key) {
                dispo = RegDisposition::REG_CREATED_NEW_KEY;
                json_value.insert(sub_key.to_string(), serde_json::json!({}));
            }

            json_value = json_value
                .get_mut(sub_key)
                .unwrap()
                .as_object_mut()
                .unwrap();
        }
        self.save_storage(&serde_json::Value::Object(storage))?;

        Ok((reg_key, dispo))
    }

    pub fn get_value<N: AsRef<OsStr>>(&self, name: N) -> std::io::Result<RegValue> {
        match self.get_raw_value(name) {
            Ok(val) => Ok(val),
            Err(err) => Err(err),
        }
    }

    pub fn get_raw_value<N: AsRef<OsStr>>(&self, name: N) -> std::io::Result<RegValue> {
        let name = name.as_ref().to_str().unwrap();
        let mut storage = self.load_storage()?;
        let json_sub_key = Self::storage_subkey(&mut storage, &self.sub_keys)?;

        let json_reg_value = match json_sub_key.get(name) {
            Some(value) => value,
            None => {
                let message = format!("Value named {name} not found");
                return Err(Error::new(std::io::ErrorKind::NotFound, message));
            }
        };

        let bytes = json_reg_value["value"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        let vtype = match json_reg_value["vtype"].as_str().unwrap() {
            "REG_NONE" => RegType::REG_NONE,
            "REG_SZ" => RegType::REG_SZ,
            "REG_EXPAND_SZ" => RegType::REG_EXPAND_SZ,
            "REG_BINARY" => RegType::REG_BINARY,
            "REG_DWORD" => RegType::REG_DWORD,
            "REG_DWORD_BIG_ENDIAN" => RegType::REG_DWORD_BIG_ENDIAN,
            "REG_LINK" => RegType::REG_LINK,
            "REG_MULTI_SZ" => RegType::REG_MULTI_SZ,
            "REG_RESOURCE_LIST" => RegType::REG_RESOURCE_LIST,
            "REG_FULL_RESOURCE_DESCRIPTOR" => RegType::REG_FULL_RESOURCE_DESCRIPTOR,
            "REG_RESOURCE_REQUIREMENTS_LIST" => RegType::REG_RESOURCE_REQUIREMENTS_LIST,
            "REG_QWORD" => RegType::REG_QWORD,
            _ => RegType::REG_NONE,
        };
        Ok(RegValue { bytes, vtype })
    }

    pub fn set_value<T: ToRegValue, N: AsRef<OsStr>>(
        &self,
        name: N,
        value: &T,
    ) -> std::io::Result<()> {
        self.set_raw_value(name, &value.to_reg_value())
    }

    pub fn set_raw_value<N: AsRef<OsStr>>(&self, name: N, value: &RegValue) -> std::io::Result<()> {
        let name = name.as_ref().to_str().unwrap();
        let mut storage = self.load_storage()?;
        let json_sub_key = Self::storage_subkey(&mut storage, &self.sub_keys)?;

        let vtype = match value.vtype {
            REG_NONE => "REG_NONE",
            REG_SZ => "REG_SZ",
            REG_EXPAND_SZ => "REG_EXPAND_SZ",
            REG_BINARY => "REG_BINARY",
            REG_DWORD => "REG_DWORD",
            REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN",
            REG_LINK => "REG_LINK",
            REG_MULTI_SZ => "REG_MULTI_SZ",
            REG_RESOURCE_LIST => "REG_RESOURCE_LIST",
            REG_FULL_RESOURCE_DESCRIPTOR => "REG_FULL_RESOURCE_DESCRIPTOR",
            REG_RESOURCE_REQUIREMENTS_LIST => "REG_RESOURCE_REQUIREMENTS_LIST",
            REG_QWORD => "REG_QWORD",
        };

        let json_reg_value = serde_json::json!({
            "value" : String::from_utf8(value.bytes.clone()).unwrap(),
            "vtype" : vtype,
        });
        json_sub_key.insert(name.to_string(), json_reg_value);

        self.save_storage(&serde_json::Value::Object(storage))
    }

    fn storage_subkey<'a>(
        storage: &'a mut serde_json::Map<String, serde_json::Value>,
        subkeys: &[String],
    ) -> std::io::Result<&'a mut serde_json::Map<String, serde_json::Value>> {
        let mut json_subkey = storage;
        for subkey in subkeys {
            let value = match json_subkey.get_mut(subkey) {
                Some(value) => value,
                None => {
                    let message = format!("Subkey {subkey} not found");
                    return Err(Error::new(std::io::ErrorKind::NotFound, message));
                }
            };

            json_subkey = match value.as_object_mut() {
                Some(value) => value,
                None => {
                    let message = format!("Json value should be a Json object");
                    return Err(Error::new(std::io::ErrorKind::InvalidData, message));
                }
            };
        }

        Ok(json_subkey)
    }

    fn load_storage(&self) -> std::io::Result<serde_json::Map<String, serde_json::Value>> {
        let file = std::fs::File::open(&self.key)?;
        let storage = serde_json::from_reader(file)?;

        Ok(storage)
    }

    fn save_storage(&self, value: &serde_json::Value) -> std::io::Result<()> {
        let file = std::fs::File::create(&self.key)?;
        serde_json::to_writer(file, value)?;

        Ok(())
    }
}

fn hkey_local_machine_data() -> serde_json::Value {
    serde_json::json!(
        {
                "SOFTWARE" :{
                    "Microsoft" :{
                        "Windows NT": {
                            "CurrentVersion" :{
                                "CurrentBuild" : {
                                    "value" : "18363",
                                    "vtype" : "REG_SZ",
                                },
                                "ProfileList" : {
                                    "S-1-5-18" : {
                                        "ProfileImagePath" : {
                                            "value" : r"%systemroot%\system32\config\systemprofile",
                                            "vtype": "REG_EXPAND_SZ",
                                        }
                                    },
                                    "S-1-5-19" : {
                                        "ProfileImagePath" : {
                                            "value" : r"%systemroot%\ServiceProfiles\LocalService",
                                            "vtype": "REG_EXPAND_SZ",
                                        }
                                    },
                                    "S-1-5-20" : {
                                        "ProfileImagePath" : {
                                            "value" : r"%systemroot%\ServiceProfiles\NetworkService",
                                            "vtype": "REG_EXPAND_SZ",
                                        }
                                    },
                                    "S-1-5-21-206651429-2786145735-121611483-1001" : {
                                        "ProfileImagePath" : {
                                            "value" : r"C:\Users\bitranox",
                                            "vtype": "REG_EXPAND_SZ",
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        }
    )
}

fn hkey_users_data() -> serde_json::Value {
    serde_json::json!(
        {
            ".DEFAULT" : {},
            "S-1-5-18" : {},
            "S-1-5-19" : {},
            "S-1-5-20" : {},
            "S-1-5-21-206651429-2786145735-121611483-1001" : {
                "Volatile Environment" : {
                    "USERNAME" : {
                        "value": "bitranox",
                        "vtype": "REG_SZ"
                    }
                }
            },
            "S-1-5-21-206651429-2786145735-121611483-1001_Classes" :  {}
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_subkey_with_value() -> std::io::Result<()> {
        let _ = std::fs::remove_file("HKEY_PERFORMANCE_TEXT");
        let key = RegKey::predef(HKEY_PERFORMANCE_TEXT)?;

        let (new_key, dispo) = key.create_subkey("NewKey")?;
        assert_eq!(dispo, RegDisposition::REG_CREATED_NEW_KEY);
        let (_, dispo) = key.create_subkey("NewKey")?;
        assert_eq!(dispo, RegDisposition::REG_OPENED_EXISTING_KEY);
        assert_eq!(new_key, key.open_subkey("NewKey")?);

        let reg_value = RegValue {
            bytes: "value".as_bytes().to_vec(),
            vtype: REG_BINARY,
        };
        new_key.set_raw_value("NewValue", &reg_value)?;

        let new_value = new_key.get_value("NewValue")?;
        assert_eq!(reg_value, new_value);

        Ok(())
    }

    #[test]
    fn predef_hkey_users() -> std::io::Result<()> {
        let key = RegKey::predef(HKEY_USERS)?;
        let _ = key.open_subkey(".DEFAULT")?;
        let _ = key.open_subkey("S-1-5-18")?;
        let _ = key.open_subkey("S-1-5-19")?;
        let _ = key.open_subkey("S-1-5-20")?;
        let _ = key.open_subkey("S-1-5-21-206651429-2786145735-121611483-1001_Classes")?;

        let vol_env =
            key.open_subkey("S-1-5-21-206651429-2786145735-121611483-1001/Volatile Environment")?;
        let username = vol_env.get_value("USERNAME")?;
        assert_eq!(username.bytes, "bitranox".as_bytes());
        assert_eq!(username.vtype, REG_SZ);

        Ok(())
    }

    #[test]
    fn predef_hkey_local_machine() -> std::io::Result<()> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)?;

        let current_version = key.open_subkey("SOFTWARE/Microsoft/Windows NT/CurrentVersion")?;
        let current_build = current_version.get_value("CurrentBuild")?;
        assert_eq!(current_build.bytes, "18363".as_bytes());
        assert_eq!(current_build.vtype, REG_SZ);

        let profile_list = current_version.open_subkey("ProfileList")?;

        let profile_image_path = profile_list
            .open_subkey("S-1-5-18")?
            .get_value("ProfileImagePath")?;
        assert_eq!(
            profile_image_path.bytes,
            r"%systemroot%\system32\config\systemprofile".as_bytes()
        );
        assert_eq!(profile_image_path.vtype, REG_EXPAND_SZ);

        let profile_image_path = profile_list
            .open_subkey("S-1-5-19")?
            .get_value("ProfileImagePath")?;
        assert_eq!(
            profile_image_path.bytes,
            r"%systemroot%\ServiceProfiles\LocalService".as_bytes()
        );
        assert_eq!(profile_image_path.vtype, REG_EXPAND_SZ);

        let profile_image_path = profile_list
            .open_subkey("S-1-5-20")?
            .get_value("ProfileImagePath")?;
        assert_eq!(
            profile_image_path.bytes,
            r"%systemroot%\ServiceProfiles\NetworkService".as_bytes()
        );
        assert_eq!(profile_image_path.vtype, REG_EXPAND_SZ);

        let profile_image_path = profile_list
            .open_subkey("S-1-5-21-206651429-2786145735-121611483-1001")?
            .get_value("ProfileImagePath")?;
        assert_eq!(profile_image_path.bytes, r"C:\Users\bitranox".as_bytes());
        assert_eq!(profile_image_path.vtype, REG_EXPAND_SZ);

        Ok(())
    }
}
