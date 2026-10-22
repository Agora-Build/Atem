//! One definition per exported type: UniFFI derives for Swift/Kotlin, serde
//! for the WASM build (plain JS objects, camelCase fields).

/// A plain data record.
macro_rules! record {
    ($(#[$m:meta])* pub struct $name:ident { $($body:tt)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
        #[cfg_attr(feature = "wasm", derive(serde::Serialize), serde(rename_all = "camelCase"))]
        pub struct $name { $($body)* }
    };
}

/// An enum (unit variants or variants with named fields); in JS an object
/// `{ "type": "<variant>", …fields }` (unit variants: `{ "type": … }`).
macro_rules! data_enum {
    ($(#[$m:meta])* pub enum $name:ident { $($body:tt)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
        #[cfg_attr(
            feature = "wasm",
            derive(serde::Serialize),
            serde(tag = "type", rename_all = "snake_case", rename_all_fields = "camelCase")
        )]
        pub enum $name { $($body)* }
    };
}

/// A unit-only enum; in JS its snake_case name as a string.
macro_rules! unit_enum {
    ($(#[$m:meta])* pub enum $name:ident { $($body:tt)* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
        #[cfg_attr(feature = "wasm", derive(serde::Serialize), serde(rename_all = "snake_case"))]
        pub enum $name { $($body)* }
    };
}
