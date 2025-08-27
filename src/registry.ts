export interface AlgorithmBinding {
  // Placeholder for future implementation
  // Will include methods for import/export, sign/verify, encode/decode
}

const registry = new Map<string, AlgorithmBinding>();

export class AlgorithmRegistry {
  static get(name: string): AlgorithmBinding | undefined {
    return registry.get(name);
  }

  static register(name: string, binding: AlgorithmBinding): void {
    registry.set(name, binding);
  }
}
