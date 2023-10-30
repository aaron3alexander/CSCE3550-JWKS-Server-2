const chai = require("chai");
const chaiHttp = require("chai-http");
const { expect } = chai;
const app = require("./server");

chai.use(chaiHttp);

describe("JWKS Server Testing Suite", () => {
  //tests the get endpoint.
  describe("GET /.well-known/jwks.json", () => {
    it("should return a valid get response", (done) => {
      chai
        .request(app)
        .get("/.well-known/jwks.json")
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res).to.be.json;
          expect(res.body).to.be.an("object");
          expect(res.body.keys).to.be.an("array");
          done();
        });
    });
  });

  describe("POST /auth", () => {
    //tests the /auth endpoint
    it("should return a valid JWT token for a valid key", (done) => {
      chai
        .request(app)
        .post("/auth")
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });
});
