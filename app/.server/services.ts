import { Config, configPath } from "./config";
import { MojangChain } from "./minecraft";
import { Store } from "./store";

export const config = Config.fromFile(configPath());

export const store = new Store(config.database);

export const minecraft = new MojangChain(
  config.microsoftClientId,
  config.microsoftClientSecret,
  config.url("/callback"),
);
