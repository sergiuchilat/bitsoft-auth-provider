export interface LogConfigInterface {
  filename: string;
  maxFiles: string;
}

export default interface AppConfigInterface {
  port: string;
  requestTimeout: number;
  security: {
    write_access_key: string;
  };
  cross_domain_token: number;
  session: {
    secret: string;
  };
  log: {
    custom: boolean;
    levels: {
      error: LogConfigInterface;
      all: LogConfigInterface;
    };
  };
}
