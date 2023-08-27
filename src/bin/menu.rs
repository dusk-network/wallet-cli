// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::fmt::Debug;
use std::collections::HashMap;
use std::hash::Hash;

use requestty::question::Choice;
use requestty::{Answer, DefaultSeparator};

#[derive(Clone, Debug)]
pub struct Menu<K> {
    items: Vec<Choice<String>>,
    keys: HashMap<usize, K>,
}

impl<K> Default for Menu<K>
where
    K: Eq + Hash + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K> Menu<K>
where
    K: Eq + Hash + Debug,
{
    pub fn new() -> Self {
        Self {
            items: vec![],
            keys: HashMap::new(),
        }
    }

    pub fn add<V>(mut self, key: K, item: V) -> Self
    where
        V: Into<Choice<String>>,
    {
        self.items.push(item.into());
        self.keys.insert(self.items.len() - 1, key);
        self
    }

    pub fn separator(mut self) -> Self {
        self.items.push(DefaultSeparator);
        self
    }

    pub fn answer(&self, answer: &Answer) -> &K {
        let index = answer.as_list_item().unwrap().index;
        let key = self.keys.get(&index);
        key.unwrap()
    }
}

impl<K> IntoIterator for Menu<K> {
    type Item = Choice<String>;
    type IntoIter = std::vec::IntoIter<Choice<String>>;
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}
