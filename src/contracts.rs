//! Explicit caller-owned codecs. Canonical protocol contracts remain generated.
use crate::client::HookError;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};
type Check = Arc<dyn Fn(&Value) -> Result<(), HookError> + Send + Sync>;

/// A single Rust type supplies both serialization and decoding. Optional
/// invariants run after decoding; no independent JSON schema is required.
pub struct Contract<T> {
    check: Check,
    marker: PhantomData<fn() -> T>,
}
impl<T> Clone for Contract<T> {
    fn clone(&self) -> Self {
        Self {
            check: self.check.clone(),
            marker: PhantomData,
        }
    }
}
impl<T: Serialize + DeserializeOwned> Default for Contract<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: Serialize + DeserializeOwned> Contract<T> {
    pub fn new() -> Self {
        Self::validated(|_| Ok(()))
    }
    pub fn validated(validate: impl Fn(&T) -> Result<(), String> + Send + Sync + 'static) -> Self {
        Self {
            check: Arc::new(move |raw| {
                let decoded: T = serde_json::from_value(raw.clone()).map_err(failure)?;
                validate(&decoded).map_err(failure)?;
                let encoded = serde_json::to_value(decoded).map_err(failure)?;
                if !retains(raw, &encoded) {
                    return Err(failure("declared codec drops or changes wire data"));
                }
                Ok(())
            }),
            marker: PhantomData,
        }
    }
    pub fn decode(&self, raw: &Value) -> Result<T, HookError> {
        (self.check)(raw)?;
        serde_json::from_value(raw.clone()).map_err(failure)
    }
}
fn failure(error: impl std::fmt::Display) -> HookError {
    HookError(error.to_string())
}
// Additional/defaulted decoded fields are allowed, but no supplied field may
// disappear or change meaning. Flattened opaque bags satisfy this requirement.
fn retains(raw: &Value, encoded: &Value) -> bool {
    match (raw, encoded) {
        (Value::Object(raw), Value::Object(encoded)) => raw
            .iter()
            .all(|(key, value)| encoded.get(key).is_some_and(|next| retains(value, next))),
        (Value::Array(raw), Value::Array(encoded)) => {
            raw.len() == encoded.len() && raw.iter().zip(encoded).all(|(a, b)| retains(a, b))
        }
        _ => raw == encoded,
    }
}
#[derive(Clone, Default)]
pub(crate) struct Admission {
    fields: BTreeMap<String, Check>,
    result: Option<Check>,
    provenance: Option<Check>,
}
impl Admission {
    pub(crate) fn field<T>(&mut self, pointer: String, contract: Contract<T>) {
        self.fields.insert(pointer, contract.check);
    }
    pub(crate) fn field_default<T>(&mut self, pointer: String, contract: Contract<T>) {
        self.fields.entry(pointer).or_insert(contract.check);
    }
    pub(crate) fn result<T>(&mut self, contract: Contract<T>) {
        self.result = Some(contract.check);
    }
    pub(crate) fn provenance<T>(&mut self, contract: Contract<T>) {
        self.provenance = Some(contract.check);
    }
    pub(crate) fn event(&self, event: &Value) -> Result<(), HookError> {
        for (pointer, check) in &self.fields {
            if let Some(value) = event.pointer(pointer) {
                check(value)?;
            }
        }
        Ok(())
    }
    pub(crate) fn returned(&self, value: &Value) -> Result<(), HookError> {
        if let Some(check) = &self.result {
            check(value)?;
        }
        Ok(())
    }
    pub(crate) fn candidate(&self, descriptor: &Value) -> Result<(), HookError> {
        if let Some(value) = descriptor.get("value") {
            self.returned(value)?;
        }
        if let Some(value) = descriptor.get("provenance")
            && let Some(check) = &self.provenance
        {
            check(value)?;
        }
        Ok(())
    }
}

/// Generator-owned candidate association, including opaque additional fields.
pub use crate::generated::Candidate;
