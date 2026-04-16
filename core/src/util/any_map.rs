use alloc::boxed::Box;
use core::any::{Any, TypeId};

use crate::os::HashMap;

#[derive(Default)]
pub struct AnyMap {
    inner: HashMap<TypeId, Box<dyn Any>>,
}

impl AnyMap {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn contains<T: Any>(&self) -> bool {
        self.inner.contains_key(&TypeId::of::<T>())
    }

    pub fn insert<T: Any>(&mut self, value: T) -> Option<T> {
        self.inner
            .insert(TypeId::of::<T>(), Box::new(value))
            .map(|boxed| *boxed.downcast::<T>().unwrap())
    }

    pub fn get<T: Any>(&self) -> Option<&T> {
        self.inner
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<T>())
    }

    pub fn get_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.inner
            .get_mut(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_mut::<T>())
    }
}
