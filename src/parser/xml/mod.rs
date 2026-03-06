// XML parser module - some methods reserved for future use
#![allow(dead_code)]

mod layout;
mod manifest;
mod menu;
mod navigation;

pub use layout::LayoutParser;
pub use manifest::ManifestParser;
pub use menu::MenuParser;
pub use navigation::NavigationParser;

use std::collections::{HashMap, HashSet};

/// A method reference from data binding (class_fqn, method_name)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct MethodReference {
    /// Fully qualified class name (e.g., "com.example.MyViewModel")
    pub class_fqn: String,
    /// Method name (e.g., "onConnectClicked")
    pub method_name: String,
}

/// Result of parsing Android XML files
#[derive(Debug, Default)]
pub struct XmlParseResult {
    /// Class names referenced in the XML
    pub class_references: HashSet<String>,

    /// Method references from data binding expressions
    /// Maps variable name to (class_fqn, method_name) for later resolution
    pub method_references: HashSet<MethodReference>,

    /// Data binding variable declarations: variable_name -> type_fqn
    pub binding_variables: HashMap<String, String>,

    /// Package name from manifest
    pub package: Option<String>,
}

impl XmlParseResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn merge(&mut self, other: XmlParseResult) {
        self.class_references.extend(other.class_references);
        self.method_references.extend(other.method_references);
        self.binding_variables.extend(other.binding_variables);
        if self.package.is_none() {
            self.package = other.package;
        }
    }
}
