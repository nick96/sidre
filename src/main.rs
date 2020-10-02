use sidre::app;

#[tokio::main]
async fn main() {
    warp::serve(app().await).run(([0, 0, 0, 0], 8080)).await;
}
