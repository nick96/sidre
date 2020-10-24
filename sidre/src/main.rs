use sidre::app;

#[tokio::main]
async fn main() {
    // Run the app on 0.0.0.0 so that it works in a container.
    warp::serve(app().await).run(([0, 0, 0, 0], 8080)).await;
}
