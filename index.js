"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getJwtHttpInterceptor = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class JwtHttpInterceptor {
    constructor(secret, config) {
        this.secret = secret;
        if (!this.secret) {
            throw new Error("JwtHttpInterceptor: secret is required");
        }
        if (!config) {
            config = {};
        }
        if (!config.expiresIn) {
            config.expiresIn = 60 * 60 * 24 * 7;
        }
        if (!config.issuer) {
            config.issuer = "localhost";
        }
        if (!config.audience) {
            config.audience = "localhost";
        }
        this.config = config;
    }
    verify(token) {
        return new Promise((resolve, reject) => {
            jsonwebtoken_1.default.verify(token, this.secret, this.config, (err, decoded) => {
                if (err) {
                    reject(err);
                }
                resolve(decoded);
            });
        });
    }
    async verifyRequest(req, res) {
        try {
            await this.verifyHeader(req, res);
        }
        catch {
            try {
                await this.verifyUrlQueryParams(req, res);
            }
            catch {
                res.statusCode = 401;
                throw new Error("JwtHttpInterceptor: token is invalid");
            }
        }
    }
    async verifyUrlQueryParams(req, res) {
        let token;
        try {
            token = this.getTokenByUrlQueryParams(req);
        }
        catch {
            throw new Error("JwtHttpInterceptor: token is required");
        }
        try {
            req.user = await this.verify(token);
        }
        catch {
            throw new Error("JwtHttpInterceptor: token is invalid");
        }
    }
    async verifyHeader(req, res) {
        let token;
        try {
            token = this.getTokenByHeader(req);
        }
        catch {
            throw new Error("JwtHttpInterceptor: token is required");
        }
        try {
            req.user = await this.verify(token);
        }
        catch {
            throw new Error("JwtHttpInterceptor: token is invalid");
        }
    }
    getTokenByUrlQueryParams(req) {
        let token;
        token = req.url.split("token=")[1]?.split("&")[0];
        if (!token) {
            throw new Error("JwtHttpInterceptor: token is required");
        }
        return token;
    }
    getTokenByHeader(req) {
        let token;
        const authorization = req.headers["Authorization"] ||
            req.headers["authorization"];
        if (!authorization) {
            throw new Error("JwtHttpInterceptor: authorization is required");
        }
        token = authorization.split(" ")[1] || authorization.split(" ")[0];
        if (!token) {
            throw new Error("JwtHttpInterceptor: token is required");
        }
        return token;
    }
}
exports.default = JwtHttpInterceptor;
function getJwtHttpInterceptor(secret, config) {
    if (!config &&
        (process.env.TOKENEXPIRESINSECONDS ||
            process.env.ISSUER ||
            process.env.AUDIENCE)) {
        config = {};
        if (process.env.TOKENEXPIRESINSECONDS) {
            config.expiresIn = Number(process.env.TOKENEXPIRESINSECONDS);
        }
        if (process.env.ISSUER) {
            config.issuer = process.env.ISSUER;
        }
        if (process.env.AUDIENCE) {
            config.audience = process.env.AUDIENCE;
        }
    }
    return new JwtHttpInterceptor(secret, config);
}
exports.getJwtHttpInterceptor = getJwtHttpInterceptor;
//# sourceMappingURL=index.js.map