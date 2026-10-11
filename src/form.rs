//! Single-declaration, restricted MCP elicitation forms.
//!
//! Enable `typed-form` and derive `Serialize`, `Deserialize`, and
//! `schemars::JsonSchema` on one flat answer struct. Unsupported JSON Schema
//! shapes or constraints fail at construction, before a request can be sent.
use crate::generated::{
    ElicitResult, McpElicitationElicitRequestFormParams,
    McpElicitationElicitRequestFormParamsRequestedSchema, McpElicitationElicitResult,
    McpElicitationElicitResultAction, McpElicitationPrimitiveSchemaDefinition, Presence,
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use std::{fmt, marker::PhantomData, sync::Arc};

/// A failure to project a schema, validate an answer, or deserialize it.
#[derive(Debug)]
pub struct FormError(String);
impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for FormError {}

/// A form response. Only an accepted form contains an answer.
#[derive(Debug, PartialEq)]
pub enum FormAnswer<T> {
    Accepted(T),
    Declined,
    Cancelled,
}

/// An immutable validated form contract for one Rust answer type.
///
/// Supports flat objects with strings, numbers, booleans, string enums, and
/// arrays of string enums. Nullable fields, nested objects, arbitrary arrays,
/// and composite schemas are deliberately rejected rather than approximated.
pub struct Form<T> {
    schema: McpElicitationElicitRequestFormParamsRequestedSchema,
    validator: Arc<jsonschema::Validator>,
    marker: PhantomData<fn() -> T>,
}

impl<T: Serialize + DeserializeOwned + JsonSchema> Form<T> {
    /// Derive and check the restricted MCP requestedSchema before use.
    pub fn new() -> Result<Self, FormError> {
        let source = serde_json::to_value(schemars::schema_for!(T)).map_err(error)?;
        let projected = project(&source)?;
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(&projected)
            .map_err(error)?;
        let schema = serde_json::from_value(projected).map_err(error)?;
        Ok(Self {
            schema,
            validator: Arc::new(validator),
            marker: PhantomData,
        })
    }

    /// Bind this one-answer contract to a public hook boundary's returned
    /// candidate admission, so invalid answers cannot reach a later interceptor.
    /// The generated result's content is the same T as this form declaration;
    /// its metadata and opaque result fields are checked without being dropped.
    pub fn result_contract(&self) -> crate::contracts::Contract<ElicitResult<T>>
    where
        T: 'static,
    {
        let form = Self {
            schema: self.schema.clone(),
            validator: self.validator.clone(),
            marker: PhantomData,
        };
        crate::contracts::Contract::validated(move |result| {
            form.decode(result)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
    }

    /// The generated wire model, not a parallel handwritten schema.
    pub fn requested_schema(&self) -> &McpElicitationElicitRequestFormParamsRequestedSchema {
        &self.schema
    }

    /// Construct the generated MCP form request params.
    pub fn request(&self, message: impl Into<String>) -> McpElicitationElicitRequestFormParams {
        McpElicitationElicitRequestFormParams::new(message, self.schema.clone())
    }

    /// Validate a generator-owned result whose content uses the same answer T.
    /// Metadata remains on the input result; admission never reconstructs or
    /// strips its opaque fields. Only accepted forms yield an answer.
    pub fn decode(&self, result: &ElicitResult<T>) -> Result<FormAnswer<T>, FormError> {
        self.decode_parts(&result.action, &result.content)
    }

    /// Validate and decode a canonical raw wire result as the declared answer T.
    /// Ordinary typed consumers use [`Self::decode`] with `ElicitResult<T>`.
    /// Missing accept content denotes an empty object, as in MCP form validation.
    pub fn decode_wire(
        &self,
        result: &McpElicitationElicitResult,
    ) -> Result<FormAnswer<T>, FormError> {
        self.decode_parts(&result.action, &result.content)
    }

    fn decode_parts<C: Serialize>(
        &self,
        action: &McpElicitationElicitResultAction,
        content: &Presence<C>,
    ) -> Result<FormAnswer<T>, FormError> {
        match action {
            McpElicitationElicitResultAction::Accept => {
                let content = match content {
                    Presence::Missing => json!({}),
                    Presence::Present(content) => serde_json::to_value(content).map_err(error)?,
                };
                self.validator.validate(&content).map_err(error)?;
                Ok(FormAnswer::Accepted(
                    crate::contracts::Contract::<T>::new()
                        .decode(&content)
                        .map_err(error)?,
                ))
            }
            McpElicitationElicitResultAction::Decline
            | McpElicitationElicitResultAction::Cancel => {
                if matches!(content, Presence::Present(_)) {
                    return Err(FormError(
                        "Content is only permitted for accepted forms".into(),
                    ));
                }
                Ok(
                    if matches!(action, McpElicitationElicitResultAction::Decline) {
                        FormAnswer::Declined
                    } else {
                        FormAnswer::Cancelled
                    },
                )
            }
            _ => Err(FormError("Unknown elicitation action".into())),
        }
    }

    /// Validate a typed answer and construct generated accepted form result params.
    pub fn accept(&self, answer: &T) -> Result<ElicitResult<T>, FormError> {
        let value = serde_json::to_value(answer).map_err(error)?;
        self.validator.validate(&value).map_err(error)?;
        let answer = crate::contracts::Contract::<T>::new()
            .decode(&value)
            .map_err(error)?;
        Ok(ElicitResult {
            meta: Presence::Missing,
            action: McpElicitationElicitResultAction::Accept,
            content: Presence::Present(answer),
            additional_properties: Default::default(),
        })
    }
}

/// URL elicitation has no answer content, including on accept.
/// Returns the generated action without inventing a typed URL answer.
pub fn decode_url_result(
    result: &McpElicitationElicitResult,
) -> Result<McpElicitationElicitResultAction, FormError> {
    reject_content(result)?;
    match &result.action {
        McpElicitationElicitResultAction::Unknown(_) => {
            Err(FormError("Unknown elicitation action".into()))
        }
        action => Ok(action.clone()),
    }
}

fn reject_content(result: &McpElicitationElicitResult) -> Result<(), FormError> {
    if matches!(result.content, Presence::Present(_)) {
        Err(FormError(
            "Content is only permitted for accepted forms".into(),
        ))
    } else {
        Ok(())
    }
}
fn error(err: impl fmt::Display) -> FormError {
    FormError(err.to_string())
}
fn unsupported(path: &str, keyword: &str) -> FormError {
    FormError(format!("Unsupported MCP form schema at {path}: {keyword}"))
}

fn project(source: &Value) -> Result<Value, FormError> {
    let root = source
        .as_object()
        .ok_or_else(|| unsupported("$", "non-object schema"))?;
    for key in root.keys() {
        if ![
            "$schema",
            "$defs",
            "title",
            "description",
            "type",
            "properties",
            "required",
            "additionalProperties",
        ]
        .contains(&key.as_str())
        {
            return Err(unsupported("$", key));
        }
    }
    if root.get("type") != Some(&json!("object")) {
        return Err(unsupported("$", "answer must be an object"));
    }
    if root
        .get("additionalProperties")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        return Err(unsupported("$", "additionalProperties"));
    }
    let empty = Map::new();
    let properties = match root.get("properties") {
        None => &empty,
        Some(value) => value
            .as_object()
            .ok_or_else(|| unsupported("$", "properties"))?,
    };
    let mut projected = Map::new();
    for (name, field) in properties {
        projected.insert(
            name.clone(),
            primitive(field, source, &format!("$.{name}"))?,
        );
    }
    let mut output = json!({"type":"object", "properties":projected});
    if let Some(required) = root.get("required") {
        output["required"] = required.clone();
    }
    if let Some(additional) = root.get("additionalProperties") {
        output["additionalProperties"] = additional.clone();
    }
    Ok(output)
}

fn primitive(field: &Value, source: &Value, path: &str) -> Result<Value, FormError> {
    primitive_inner(field, source, path, true)
}
fn primitive_inner(
    field: &Value,
    source: &Value,
    path: &str,
    allow_array: bool,
) -> Result<Value, FormError> {
    let mut schema = field
        .as_object()
        .cloned()
        .ok_or_else(|| unsupported(path, "boolean schema"))?;
    // Resolve only local definitions. References to references or recursive shapes
    // are rejected by the same keyword check below, with no unbounded recursion.
    if let Some(reference) = schema.remove("$ref") {
        let reference = reference
            .as_str()
            .ok_or_else(|| unsupported(path, "$ref"))?;
        if !reference.starts_with("#/$defs/") {
            return Err(unsupported(path, "$ref"));
        }
        let target = source
            .pointer(&reference[1..])
            .and_then(Value::as_object)
            .ok_or_else(|| unsupported(path, "unresolved $ref"))?;
        let mut resolved = target.clone();
        for (key, value) in schema {
            if resolved.contains_key(&key) && resolved[&key] != value {
                return Err(unsupported(path, "conflicting $ref sibling"));
            }
            resolved.insert(key, value);
        }
        schema = resolved;
    }
    // Schemars' numeric format labels are annotations, not JSON Schema
    // assertions. MCP numbers have no format member; keep all numeric bounds.
    if matches!(
        schema.get("type").and_then(Value::as_str),
        Some("integer" | "number")
    ) && let Some(format) = schema.remove("format")
        && ![
            "int8", "int16", "int32", "int64", "int128", "int", "uint8", "uint16", "uint32",
            "uint64", "uint128", "uint", "float", "double",
        ]
        .iter()
        .any(|known| format == *known)
    {
        return Err(unsupported(path, "numeric format"));
    }
    let kind = schema
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported(path, "nullable/composite or missing type"))?;
    if !allow_array && kind != "string" {
        return Err(unsupported(path, "items must be a string enum"));
    }
    let specific: &[&str] = match kind {
        "string" => &["minLength", "maxLength", "format", "enum"],
        "integer" | "number" => &["minimum", "maximum"],
        "boolean" => &[],
        "array" => &["items", "minItems", "maxItems"],
        _ => return Err(unsupported(path, kind)),
    };
    for key in schema.keys() {
        if !["type", "title", "description", "default"].contains(&key.as_str())
            && !specific.contains(&key.as_str())
        {
            return Err(unsupported(path, key));
        }
    }
    if kind == "string" {
        if let Some(format) = schema.get("format")
            && !["date", "date-time", "email", "uri"]
                .iter()
                .any(|allowed| format == allowed)
        {
            return Err(unsupported(path, "format"));
        }
        if let Some(values) = schema.get("enum") {
            string_enum(values, path)?;
        }
    }
    if kind == "array" {
        let items = schema
            .get("items")
            .ok_or_else(|| unsupported(path, "missing items"))?;
        let items = primitive_inner(items, source, &format!("{path}.items"), false)?;
        let object = items.as_object().expect("primitive returns an object");
        if object
            .keys()
            .any(|key| !["type", "enum"].contains(&key.as_str()))
            || object.get("type") != Some(&json!("string"))
        {
            return Err(unsupported(path, "items must be an unadorned string enum"));
        }
        string_enum(
            object
                .get("enum")
                .ok_or_else(|| unsupported(path, "array requires string enum"))?,
            path,
        )?;
        schema.insert("items".into(), items);
    }
    let value = Value::Object(schema);
    // Reuse the canonical primitive union's structural decoder. It permits
    // extensions, so the stricter keyword checks above must run first.
    serde_json::from_value::<McpElicitationPrimitiveSchemaDefinition>(value.clone())
        .map_err(error)?;
    Ok(value)
}
fn string_enum(values: &Value, path: &str) -> Result<(), FormError> {
    let values = values.as_array().ok_or_else(|| unsupported(path, "enum"))?;
    if values.is_empty() || values.iter().any(|v| !v.is_string()) {
        return Err(unsupported(path, "enum must contain strings"));
    }
    Ok(())
}
