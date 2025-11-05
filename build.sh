#!/bin/bash

echo "🚀 Building Atem - Rust TUI with WebSocket support"
echo "=================================================="

# Check if Rust is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Cargo not found"
    echo "   Please install Rust: https://rustup.rs/"
    exit 1
fi

echo "✅ Rust found, building project..."

# Clean and build
cargo clean
echo "🔨 Compiling Rust sources..."
cargo build --release

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo ""
    echo "📦 Executable location:"
    echo "   target/release/atem"
    echo ""
    echo "🚀 Usage examples:"
    echo "   # CLI mode - generate token"
    echo "   ./target/release/atem token rtc create"
    echo ""
    echo "   # Interactive TUI mode"
    echo "   ./target/release/atem"
    echo ""
    echo "🔌 WebSocket Integration:"
    echo "   • Atem will try to connect to Astation at ws://127.0.0.1:8080/ws"
    echo "   • If connected, projects and tokens will come from Astation"
    echo "   • If not connected, fallback to local demo mode"
    echo ""
    echo "💡 To test with Astation:"
    echo "   1. Start Astation on macOS: cd ../Astation && swift run"
    echo "   2. Start Atem: ./target/release/atem"
    echo "   3. Atem will connect to Astation automatically"
else
    echo "❌ Build failed!"
    exit 1
fi