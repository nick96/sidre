use prost::{bytes::BytesMut, Message};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    SledError(#[from] sled::Error),
    #[error(transparent)]
    ProstDecodeError(#[from] prost::DecodeError),
    #[error(transparent)]
    ProstEncodeError(#[from] prost::EncodeError),
}

pub type Result<T> = std::result::Result<T, Error>;
pub struct ProtoDb(sled::Db);

/// ProtoDb is a trait intended to be used to provide extension methods to
/// [sled::Db].
///
/// [ProtoDb] provides methods to make it easier store and retrieve protobuf
/// encoded data in a Sled database.
impl ProtoDb {
    /// Get a value by its key.
    pub fn get<K, T>(&self, key: K) -> Result<Option<T>>
    where
        K: AsRef<[u8]>,
        T: Message + Default,
    {
        let maybe_data = self.0.get(key)?;
        if let Some(data) = maybe_data {
            let msg = T::decode(&*data)?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Atomically retrieve then update a value.
    pub fn update_and_fetch<K, V, F, T>(
        &self,
        key: K,
        mut f: F,
    ) -> Result<Option<T>>
    where
        K: AsRef<[u8]>,
        F: FnMut(Option<T>) -> Option<V>,
        V: Into<T>,
        T: Message + Default,
    {
        // Escape the scoping of the closure so we can report the error.
        let mut err: Option<Error> = None;
        let maybe_data = self.0.update_and_fetch(key, |maybe_data| {
            let maybe_msg = if let Some(data) = maybe_data {
                match T::decode(data) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        err = Some(e.into());
                        None
                    },
                }
            } else {
                None
            };
            if let Some(inserted) = f(maybe_msg) {
                let mut buf = BytesMut::default();
                let inserted_msg: T = inserted.into();
                if let Err(e) = inserted_msg.encode(&mut buf) {
                    err = Some(e.into());
                    None
                } else {
                    Some(buf.as_bytes())
                }
            } else {
                None
            }
        })?;

        if let Some(e) = err {
            return Err(e);
        }

        if let Some(data) = maybe_data {
            let msg = T::decode(&*data)?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Insert a value into the database.
    pub fn insert<K, V, T>(&self, key: K, value: V) -> Result<Option<T>>
    where
        K: AsRef<[u8]>,
        V: Into<T>,
        T: Message + Default,
    {
        let mut buf = BytesMut::default();
        let msg: T = value.into();
        msg.encode(&mut buf)?;
        let maybe_inserted = self.0.insert(key, buf.as_bytes())?;
        if let Some(inserted) = maybe_inserted {
            let msg = T::decode(&*inserted)?;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }
}

trait BytesMutAsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

impl BytesMutAsBytes for BytesMut {
    fn as_bytes(&self) -> Vec<u8> {
        let bytes: &[u8] = &self;
        bytes.to_owned()
    }
}

#[cfg(test)]
mod test {
    use once_cell::sync::OnceCell;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use super::ProtoDb;

    mod messages {
        include!(concat!(env!("OUT_DIR"), "/messages.rs"));
    }

    fn random_key() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect()
    }

    fn proto_db() -> ProtoDb {
        static DB: OnceCell<sled::Db> = OnceCell::new();
        let db = DB.get_or_init(|| {
            sled::open("/tmp/prost-sled-test")
                .expect("failed to open sled DB for test")
        });
        ProtoDb(db.to_owned())
    }

    #[test]
    fn get_exists() {
        let db = proto_db();
        let thing = messages::Thing::default();
        let key = random_key();
        let _: Option<messages::Thing> =
            db.insert(&key, thing.clone()).unwrap();
        let retrieved = db.get(&key).unwrap().unwrap();
        assert_eq!(thing, retrieved);
    }

    #[test]
    fn get_no_exist() {
        let db = proto_db();
        let key = random_key();
        let retrieved: Option<messages::Thing> = db.get(&key).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn update_and_fetch_existing() {
        let db = proto_db();
        let thing = messages::Thing::default();
        let key = random_key();
        let _: Option<messages::Thing> =
            db.insert(&key, thing.clone()).unwrap();
        let updated = db
            .update_and_fetch(&key, |maybe_msg| {
                let mut msg: messages::Thing = maybe_msg.unwrap();
                msg.i = "test".into();
                Some(msg)
            })
            .unwrap();
        let expected = messages::Thing {
            i: "test".into(),
            ..Default::default()
        };
        assert_eq!(updated, Some(expected));
    }

    #[test]
    fn update_and_fetch_no_existing() {
        let db = proto_db();
        let key = random_key();
        let updated = db
            .update_and_fetch(&key, |maybe_msg| {
                assert!(maybe_msg.is_none());
                let mut msg = messages::Thing::default();
                msg.i = "test".into();
                Some(msg)
            })
            .unwrap();
        let expected = messages::Thing {
            i: "test".into(),
            ..Default::default()
        };
        assert_eq!(updated, Some(expected));
    }

    #[test]
    fn insert_not_existing() {
        let db = proto_db();
        let key = random_key();
        let thing = messages::Thing::default();
        let previous: Option<messages::Thing> =
            db.insert(&key, thing.clone()).unwrap();
        assert!(previous.is_none());
        let inserted: messages::Thing = db.get(&key).unwrap().unwrap();
        assert_eq!(inserted, thing);
    }

    #[test]
    fn insert_existing() {
        let db = proto_db();
        let key = random_key();
        let first_thing = messages::Thing::default();
        let previous: Option<messages::Thing> =
            db.insert(&key, first_thing.clone()).unwrap();
        assert!(previous.is_none());
        let inserted: messages::Thing = db.get(&key).unwrap().unwrap();
        assert_eq!(inserted, first_thing);

        let second_thing = messages::Thing {
            i: random_key(),
            ..Default::default()
        };
        let second_inserted: messages::Thing =
            db.insert(&key, second_thing.clone()).unwrap().unwrap();
        assert_eq!(first_thing, second_inserted);
        let retieved: messages::Thing = db.get(&key).unwrap().unwrap();
        assert_eq!(retieved, second_thing);
    }
}
