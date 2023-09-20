#![no_main]

use arbitrary::Arbitrary;
use std::collections::HashMap;
use libfuzzer_sys::fuzz_target;
use routinator::utils::archive::{
    AccessError, Archive, ArchiveError, ObjectMeta, PublishError,
    StorageRead, StorageWrite,
};

#[derive(Arbitrary, Clone, Debug)]
enum Op {
    Publish { name: Vec<u8>, data: Vec<u8> },
    Update { name: Vec<u8>, data: Vec<u8> },
    Delete { name: Vec<u8> },
}

struct Meta;

impl ObjectMeta for Meta {
    const SIZE: usize = 4;
    type ConsistencyError = ();

    fn write(
        &self, write: &mut StorageWrite
    ) -> Result<(), ArchiveError> {
        write.write(b"abcd")
    }

    fn read(
        read: &mut StorageRead
    ) -> Result<Self, ArchiveError> {
        let slice = read.read_slice(4).unwrap();
        assert_eq!(slice.as_ref(), b"abcd");
        Ok(Meta)
    }
}

fn check_archive(
    archive: &Archive<Meta>,
    content: &HashMap<Vec<u8>, Vec<u8>>,
) {
    archive.verify().unwrap();
    let mut content = content.clone();
    for item in archive.objects().unwrap() {
        let (name, _, data) = item.unwrap();
        assert_eq!(
            content.remove(name.as_ref()).as_ref().map(|x| x.as_slice()),
            Some(data.as_ref())
        );
    }
    assert!(content.is_empty());
}

fn run_archive(ops: impl IntoIterator<Item = Op>) {
    let mut archive = Archive::create_with_file(
        tempfile::tempfile().unwrap()
    ).unwrap();
    let mut content = HashMap::new();

    for item in ops {
        match item {
            Op::Publish { name, data } => {
                if name.is_empty() { continue }
                let res = archive.publish(name.as_ref(), &Meta, data.as_ref());
                if content.contains_key(&name) {
                    assert!(matches!(res, Err(PublishError::AlreadyExists)))
                }
                else {
                    content.insert(name, data);
                    assert!(matches!(res, Ok(())));
                }
            }
            Op::Update { name, data } => {
                if name.is_empty() { continue }
                let res = archive.update(
                    name.as_ref(), &Meta, data.as_ref(), |_| Ok(())
                );
                if content.contains_key(&name) {
                    content.insert(name, data);
                    assert!(matches!(res, Ok(())));
                }
                else {
                    assert!(matches!(res, Err(AccessError::NotFound)))
                }
            }
            Op::Delete { name } => {
                if name.is_empty() { continue }
                let res = archive.delete(name.as_ref(), |_| Ok(()));
                if content.remove(name.as_slice()).is_some() {
                    assert!(matches!(res, Ok(())))
                }
                else {
                    assert!(matches!(res, Err(AccessError::NotFound)))
                }
            }
        }

        check_archive(&archive, &content);
    }
}

fuzz_target!{|actions: Vec<Op>| {
    run_archive(actions)
}}
