// Prevents a terminal window on Windows in release mode
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    anya_gui_lib::run();
}
