import type FalkorDBCanvas from "@falkordb/canvas";
import type { DetailedHTMLProps, HTMLAttributes } from "react";

// React 19 reads intrinsic elements from React.JSX, not the global JSX namespace the package declares.
declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "falkordb-canvas": DetailedHTMLProps<HTMLAttributes<FalkorDBCanvas>, FalkorDBCanvas>;
    }
  }
}
