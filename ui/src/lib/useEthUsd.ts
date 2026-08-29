import { useEffect, useState } from 'react';

/**
 * Best-effort ETH/USD spot price for value context next to amounts.
 * Returns null (and shows nothing) when the fetch fails — never blocks.
 */
export function useEthUsd(): number | null {
  const [price, setPrice] = useState<number | null>(null);
  useEffect(() => {
    let alive = true;
    fetch('https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd')
      .then((r) => r.json())
      .then((j) => { if (alive) setPrice(j?.ethereum?.usd ?? null); })
      .catch(() => {});
    return () => { alive = false; };
  }, []);
  return price;
}

export function usd(eth: number, price: number | null): string {
  if (price == null || !Number.isFinite(eth)) return '';
  return ` (~$${(eth * price).toLocaleString(undefined, { maximumFractionDigits: 2 })})`;
}
