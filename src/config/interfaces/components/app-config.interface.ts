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
  app_two_fa_connected: number;
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
