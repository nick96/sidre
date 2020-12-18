use sidre::{app, store};

// Determine whether or not we should use the persistent store.
//
// Currently this is just based on compile time features but I can imagine a
// world where we may want to compile both features and chose one or the other
// based on a command line flag or environment variable.
fn should_use_persistent_store() -> bool {
    if cfg!(feature = "data-in-memory") {
        false
    } else {
        true
    }
}

#[tokio::main]
async fn main() {
    let store = if should_use_persistent_store() {
        unimplemented!()
    } else {
        store::MemoryStore::new()
    };

    // Run the app on 0.0.0.0 so that it works in a container.
    warp::serve(app(store).await)
        .run(([0, 0, 0, 0], 8080))
        .await;
}
