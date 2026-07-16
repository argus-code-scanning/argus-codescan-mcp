declare module "eslint-plugin-security" {
  import type { Linter } from "eslint";
  const plugin: {
    configs: {
      recommended: Linter.Config | Linter.Config[];
    };
  };
  export default plugin;
}
