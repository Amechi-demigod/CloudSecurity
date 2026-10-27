import { useEffect, useState } from "react";
import { api } from "../api";

/** Product name and tagline (BRAND_NAME / BRAND_TAGLINE on the server, public via /api/health). */
export interface Brand {
  name: string;
  tagline: string;
}

export const DEFAULT_BRAND: Brand = { name: "CloudSecurity", tagline: "Runtime-first CNAPP" };

let cached: Brand | null = null;
let pending: Promise<Brand> | null = null;

function loadBrand(): Promise<Brand> {
  pending ??= api
    .health()
    .then((h) => (cached = h.brand ?? DEFAULT_BRAND))
    .catch(() => DEFAULT_BRAND);
  return pending;
}

/** The brand, fetched once per page load; the default is used until it arrives (and if the server is unreachable). */
export function useBrand(): Brand {
  const [brand, setBrand] = useState<Brand>(cached ?? DEFAULT_BRAND);
  useEffect(() => {
    let live = true;
    loadBrand().then((b) => {
      if (live) setBrand(b);
      document.title = b.name;
    });
    return () => {
      live = false;
    };
  }, []);
  return brand;
}

/** Synchronous best guess, for code outside React (e.g. file names); call useBrand() somewhere first. */
export const currentBrand = (): Brand => cached ?? DEFAULT_BRAND;
