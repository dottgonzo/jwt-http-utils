import jwt from "jsonwebtoken";

import { IncomingMessage, ServerResponse } from "http";

export type TJWTConfig = {
  expiresIn: number;
  issuer: string;
  audience: string;
};
export type TJWTUser = {};
export default class JwtHttpInterceptor {
  secret: string;
  config: TJWTConfig;
  constructor(secret: string, config?: TJWTConfig) {
    this.secret = secret;
    if (!this.secret) {
      throw new Error("JwtHttpInterceptor: secret is required");
    }
    if (!config) {
      config = {} as TJWTConfig;
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
  verify(token: string) {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        this.secret,
        this.config,
        (err: Error, decoded: any) => {
          if (err) {
            reject(err);
          }
          resolve(decoded);
        }
      );
    });
  }
  async verifyRequest(
    req: IncomingMessage & { user: TJWTUser },
    res: ServerResponse<IncomingMessage> & {
      req: IncomingMessage;
    }
  ) {
    try {
      await this.verifyHeader(req, res);
    } catch {
      try {
        await this.verifyUrlQueryParams(req, res);
      } catch {
        res.statusCode = 401;
        throw new Error("JwtHttpInterceptor: token is invalid");
      }
    }
  }
  async verifyUrlQueryParams(
    req: IncomingMessage & { user: TJWTUser },
    res: ServerResponse<IncomingMessage> & {
      req: IncomingMessage;
    }
  ) {
    let token: string;
    try {
      token = this.getTokenByUrlQueryParams(req);
    } catch {
      res.statusCode = 401;
      throw new Error("JwtHttpInterceptor: token is required");
    }
    try {
      req.user = await this.verify(token);
    } catch {
      res.statusCode = 401;
      throw new Error("JwtHttpInterceptor: token is invalid");
    }
  }
  async verifyHeader(
    req: IncomingMessage & { user: TJWTUser },
    res: ServerResponse<IncomingMessage> & {
      req: IncomingMessage;
    }
  ) {
    let token: string;
    try {
      token = this.getTokenByHeader(req);
    } catch {
      res.statusCode = 401;
      throw new Error("JwtHttpInterceptor: token is required");
    }
    try {
      req.user = await this.verify(token);
    } catch {
      res.statusCode = 401;
      throw new Error("JwtHttpInterceptor: token is invalid");
    }
  }
  getTokenByUrlQueryParams(req: IncomingMessage): string {
    let token: string;
    token = req.url.split("token=")[1]?.split("&")[0];
    if (!token) {
      throw new Error("JwtHttpInterceptor: token is required");
    }
    return token;
  }
  getTokenByHeader(req: IncomingMessage): string {
    let token: string;
    const authorization = req.headers["Authorization"] as string;
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

export function getJwtHttpInterceptor(
  secret: string,
  config?: TJWTConfig
): JwtHttpInterceptor {
  if (
    !config &&
    (process.env.TOKENEXPIRESINSECONDS ||
      process.env.ISSUER ||
      process.env.AUDIENCE)
  ) {
    config = {} as TJWTConfig;
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
