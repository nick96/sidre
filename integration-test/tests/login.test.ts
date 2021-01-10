jest.setTimeout(40 * 1000)

describe("Login", () => {
        describe("when the Login button is clicked", () => {
                beforeEach(async () => {
                        await page.goto("http://localhost:5000");
                        await page.click("[data-test-label=login]");
                })

                it("should log you in", async () => {
                        await expect(page).toHaveSelector("[data-test-label=logout]", { state: "attached" });
                });
        });
});
