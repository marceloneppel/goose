use crate::mcp_utils::ToolResult;
use rmcp::model::{ErrorCode, ErrorData};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;

pub fn serialize<T, S>(value: &ToolResult<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    match value {
        Ok(val) => {
            let mut state = serializer.serialize_struct("ToolResult", 2)?;
            state.serialize_field("status", "success")?;
            state.serialize_field("value", val)?;
            state.end()
        }
        Err(err) => {
            let mut state = serializer.serialize_struct("ToolResult", 2)?;
            state.serialize_field("status", "error")?;
            state.serialize_field("error", &err.to_string())?;
            state.end()
        }
    }
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<ToolResult<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ResultFormat<T> {
        Success { status: String, value: T },
        Error { status: String, error: String },
    }

    let format = ResultFormat::deserialize(deserializer)?;

    match format {
        ResultFormat::Success { status, value } => {
            if status == "success" {
                Ok(Ok(value))
            } else {
                Err(serde::de::Error::custom(format!(
                    "Expected status 'success', got '{}'",
                    status
                )))
            }
        }
        ResultFormat::Error { status, error } => {
            if status == "error" {
                Ok(Err(ErrorData {
                    code: ErrorCode::INTERNAL_ERROR,
                    message: Cow::from(error),
                    data: None,
                }))
            } else {
                Err(serde::de::Error::custom(format!(
                    "Expected status 'error', got '{}'",
                    status
                )))
            }
        }
    }
}

pub mod call_tool_result {
    use super::*;
    use rmcp::model::{CallToolResult, Content};
    use serde_json::Value;

    pub fn serialize<S>(
        value: &ToolResult<CallToolResult>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        super::serialize(value, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ToolResult<CallToolResult>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Helper struct for deserializing CallToolResult with empty content
        // rmcp's CallToolResult requires non-empty content OR structured_content,
        // but sessions may have been serialized with empty content arrays.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawCallToolResult {
            #[serde(default)]
            content: Vec<Content>,
            #[serde(default)]
            is_error: Option<bool>,
            #[serde(default)]
            structured_content: Option<Value>,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ResultFormat {
            NewSuccess {
                status: String,
                value: RawCallToolResult,
            },
            LegacySuccess {
                status: String,
                value: Vec<Content>,
            },
            Error {
                status: String,
                error: String,
            },
        }

        let format = ResultFormat::deserialize(deserializer)?;

        match format {
            ResultFormat::NewSuccess { status, value } => {
                if status == "success" {
                    // Handle empty content arrays by providing a default empty text
                    let content = if value.content.is_empty() && value.structured_content.is_none()
                    {
                        vec![Content::text("(empty result)")]
                    } else {
                        value.content
                    };

                    let result = if value.is_error.unwrap_or(false) {
                        CallToolResult::error(content)
                    } else {
                        CallToolResult::success(content)
                    };
                    Ok(Ok(result))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Expected status 'success', got '{}'",
                        status
                    )))
                }
            }
            ResultFormat::LegacySuccess { status, value } => {
                if status == "success" {
                    Ok(Ok(CallToolResult::success(value)))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Expected status 'success', got '{}'",
                        status
                    )))
                }
            }
            ResultFormat::Error { status, error } => {
                if status == "error" {
                    Ok(Err(ErrorData {
                        code: ErrorCode::INTERNAL_ERROR,
                        message: Cow::from(error),
                        data: None,
                    }))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Expected status 'error', got '{}'",
                        status
                    )))
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::mcp_utils::ToolResult;
        use rmcp::model::RawContent;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestToolResponse {
            #[serde(deserialize_with = "deserialize")]
            tool_result: ToolResult<CallToolResult>,
        }

        #[test]
        fn test_deserialize_empty_content_array() {
            // This is the exact format that caused the session resume failure
            let json =
                r#"{"tool_result":{"status":"success","value":{"content":[],"isError":false}}}"#;
            let result: TestToolResponse = serde_json::from_str(json).unwrap();
            let call_result = result.tool_result.unwrap();

            // Should have converted empty content to "(empty result)"
            assert_eq!(call_result.content.len(), 1);
            if let RawContent::Text(text_content) = &call_result.content[0].raw {
                assert_eq!(text_content.text, "(empty result)");
            } else {
                panic!("Expected text content");
            }
        }

        #[test]
        fn test_deserialize_new_format_with_content() {
            let json = r#"{"tool_result":{"status":"success","value":{"content":[{"type":"text","text":"hello"}],"isError":false}}}"#;
            let result: TestToolResponse = serde_json::from_str(json).unwrap();
            let call_result = result.tool_result.unwrap();

            assert_eq!(call_result.content.len(), 1);
            if let RawContent::Text(text_content) = &call_result.content[0].raw {
                assert_eq!(text_content.text, "hello");
            } else {
                panic!("Expected text content");
            }
        }

        #[test]
        fn test_deserialize_legacy_format() {
            let json =
                r#"{"tool_result":{"status":"success","value":[{"type":"text","text":"legacy"}]}}"#;
            let result: TestToolResponse = serde_json::from_str(json).unwrap();
            let call_result = result.tool_result.unwrap();

            assert_eq!(call_result.content.len(), 1);
            if let RawContent::Text(text_content) = &call_result.content[0].raw {
                assert_eq!(text_content.text, "legacy");
            } else {
                panic!("Expected text content");
            }
        }

        #[test]
        fn test_deserialize_error_format() {
            let json = r#"{"tool_result":{"status":"error","error":"something went wrong"}}"#;
            let result: TestToolResponse = serde_json::from_str(json).unwrap();

            assert!(result.tool_result.is_err());
            let error = result.tool_result.unwrap_err();
            assert_eq!(error.message.as_ref(), "something went wrong");
        }

        #[test]
        fn test_deserialize_is_error_true() {
            let json = r#"{"tool_result":{"status":"success","value":{"content":[{"type":"text","text":"error msg"}],"isError":true}}}"#;
            let result: TestToolResponse = serde_json::from_str(json).unwrap();
            let call_result = result.tool_result.unwrap();

            assert!(call_result.is_error.unwrap_or(false));
        }
    }
}
