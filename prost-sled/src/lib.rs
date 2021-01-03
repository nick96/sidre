//! prost-sled: An integration layer between [prost] and [sled].
//!
//! prost-sled makes it easy to store protobufs in a sled database because
//! it abstracts away the boilerplate of encoding and decoding the protobufs.
//! If for any reason you wish to interact with the raw bytes instead or
//! [sled::Db] implements a method that [ProtoDb] doesn't yet, you can simply
//! use the `from` and `into` methods of the corresponding types as [From] and
//! [Into] are implemented as a go between, between the two types.

use prost::{bytes::BytesMut, Message};
use thiserror::Error;

/// Errors that can be returned by this library. It's really a simple
/// integration layer to encompass the possible errors returned by [sled] and
/// [prost].
#[derive(Debug, Error)]
pub enum Error {
    /// An error was returned by [sled].
    #[error(transparent)]
    SledError(#[from] sled::Error),
    /// A decoding error ([prost::DecodeError]) occurred in [prost].
    #[error(transparent)]
    ProstDecodeError(#[from] prost::DecodeError),
    /// An encoding error ([prost::EncodeError]) occurred in [prost].
    #[error(transparent)]
    ProstEncodeError(#[from] prost::EncodeError),
}

/// Result of a database action. That is, either some type `T` or an
/// [enum@Error].
pub type Result<T> = std::result::Result<T, Error>;

/// Wrapper around [sled::Db] that allows you to use types implementing
/// [prost::Message] instead of raw bytes.
pub struct ProtoDb(sled::Db);

/// Convenience implementation to convert an existing [sled::Db] to a [ProtoDb].
impl From<ProtoDb> for sled::Db {
    fn from(db: ProtoDb) -> Self {
        db.0
    }
}

/// Escape hatch to get from a [ProtoDb] to a [sled::Db] in-case you need
/// something more low level.
impl From<sled::Db> for ProtoDb {
    fn from(db: sled::Db) -> Self {
        Self(db)
    }
}

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

/// Convenience trait to convert to stdlib bytes. This is intended only for
/// internal use (hence not `pub`) and is only implemented for `BytesMut`.
trait BytesMutAsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

/// Conversion between `BytesMut` and `Vec<u8>`. This is just a convenience as
/// `sled` works with `Vec<u8>` and `prost` uses `BytesMut`.
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
