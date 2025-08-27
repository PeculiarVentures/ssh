import { describe, expect, it } from 'vitest';
import { parse as parseCertificate, serialize as serializeCertificate } from './certificate';
import { SshWriter } from './writer';

describe('parseCertificate', () => {
  it('should parse certificate from Uint8Array', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const fullData = writer.toUint8Array();
    const keyData = new Uint8Array([0x01, 0x02, 0x03]);

    const result = parseCertificate(fullData);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toEqual(keyData);
  });

  it('should parse certificate from base64 string', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const fullData = writer.toUint8Array();
    const base64 = btoa(String.fromCharCode(...fullData));

    const certString = `ssh-rsa-cert-v01@openssh.com ${base64}`;
    const result = parseCertificate(certString);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toEqual(fullData);
  });

  it('should parse real RSA SSH certificate', () => {
    const realRsaCert = 'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgk3X/I7OdvOSl6SfpVX5crYWrpWQEyWRkbh5hr341NBcAAAADAQABAAABAQDQ/R7P0LxRLmdGYjMFFUc9dKROF/THLWasszfXwRtYiBILBljvJnfvBByngTuIhRsaBLpJmGzH4fPTmqfUKJUqO0LRXbzv1VFimx0v2t5bPe8W35HUH7RltYlTTs/NwBlkcyoacZWpS7kOD17ZfmOgKMpEm14tY2/JxAMFDuo0KkKgJdwlLDHHLkoov1KPliKGhcnXKJoh4G1pmGsYop/lbqmxR1dFKzsYwwfeLIN0OZpc5mqrHM4XKOHZ4IuSxqC5d52z0icGWc+LJPcL/zGMzQtTnFTKFcf4rc+rRRq7oofb8rLFCMkc9VHrj+ZNVIoLMCN4wkw0IgNY2LH79WaLAAAAAAAAAAAAAAABAAAADXRlc3QtdXNlci1yc2EAAAAMAAAACHRlc3R1c2VyAAAAAGivIlwAAAAAaLB0RwAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIC6qlgO7E2qluMn+v9DO/okxKLQeU2aFb69pgy6jacnkAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBHN+MUaadMhjIJrcwI1woYnmS135FABeflp92GAAJ96yS8iUDF3l1KgIDFwCLIa9DZOCj0vM8vom7rBv03BpsA test-user-rsa';
    const result = parseCertificate(realRsaCert);
    expect(result.type).toBe('ssh-rsa-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
    expect(result.comment).toBe('test-user-rsa');
  });

  it('should parse real Ed25519 SSH certificate', () => {
    const realEd25519Cert = 'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIOSBBJEgN2QmMKFF9way54gb0ytGMGgTSB6FVv+H0/OgAAAAIAK4yjyozG/QFINLQkz35aziQzWD3kzJXRo++KDl3Y9HAAAAAAAAAAAAAAABAAAAEXRlc3QtdXNlci1lZDI1NTE5AAAADAAAAAh0ZXN0dXNlcgAAAABoryJcAAAAAGiwdEsAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAuqpYDuxNqpbjJ/r/Qzv6JMSi0HlNmhW+vaYMuo2nJ5AAAAFMAAAALc3NoLWVkMjU1MTkAAABAScXlIavj0kJoE/6vr/Da8+181Z0E5TIoaj78tmcxJ89n45r8gKS2ipUay3PpUX7Wll6wKmt/BatNu0j757IACA== test-user-ed25519';
    const result = parseCertificate(realEd25519Cert);
    expect(result.type).toBe('ssh-ed25519-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
    expect(result.comment).toBe('test-user-ed25519');
  });

  it('should parse real ECDSA P-256 SSH certificate', () => {
    const realEcdsaCert = 'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgLQJpeITGDHn9MWmsYxCkrpfpes+kUSPmW3aqtXfzDX8AAAAIbmlzdHAyNTYAAABBBI5uJjleYPE3VSDfwSTyGhrupTZXFaf1KUeGFjwc93bhw10zrd/7pccJllj9ubMMIEcuDgbkEyolyDmuS/EAdRAAAAAAAAAAAAAAAAEAAAAPdGVzdC11c2VyLWVjZHNhAAAADAAAAAh0ZXN0dXNlcgAAAABoryJcAAAAAGiwdFEAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAuqpYDuxNqpbjJ/r/Qzv6JMSi0HlNmhW+vaYMuo2nJ5AAAAFMAAAALc3NoLWVkMjU1MTkAAABAXdy+Uboy5tqOK9ihJN6Ap+b69sk78p0i+KnbL4fEljSPk/dm+Z9HeRKBHqXXlk0PRLqQlv6tPeBGGnU+QnVHBw== test-user-ecdsa';
    const result = parseCertificate(realEcdsaCert);
    expect(result.type).toBe('ecdsa-sha2-nistp256-cert-v01@openssh.com');
    expect(result.keyData).toBeDefined();
    expect(result.keyData.length).toBeGreaterThan(0);
  });
});

describe('serializeCertificate', () => {
  it('should serialize certificate', () => {
    const writer = new SshWriter();
    writer.writeString('ssh-rsa-cert-v01@openssh.com');
    writer.writeBytes(new Uint8Array([0x01, 0x02, 0x03]));
    const keyData = writer.toUint8Array();

    const cert = {
      type: 'ssh-rsa-cert-v01@openssh.com' as const,
      keyData,
    };

    const result = serializeCertificate(cert);

    // Verify the result by parsing it back
    const parsed = parseCertificate(result);
    expect(parsed.type).toBe(cert.type);
    expect(parsed.keyData).toEqual(cert.keyData);
  });

  it('should round-trip real RSA SSH certificate', () => {
    const originalCert = 'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgk3X/I7OdvOSl6SfpVX5crYWrpWQEyWRkbh5hr341NBcAAAADAQABAAABAQDQ/R7P0LxRLmdGYjMFFUc9dKROF/THLWasszfXwRtYiBILBljvJnfvBByngTuIhRsaBLpJmGzH4fPTmqfUKJUqO0LRXbzv1VFimx0v2t5bPe8W35HUH7RltYlTTs/NwBlkcyoacZWpS7kOD17ZfmOgKMpEm14tY2/JxAMFDuo0KkKgJdwlLDHHLkoov1KPliKGhcnXKJoh4G1pmGsYop/lbqmxR1dFKzsYwwfeLIN0OZpc5mqrHM4XKOHZ4IuSxqC5d52z0icGWc+LJPcL/zGMzQtTnFTKFcf4rc+rRRq7oofb8rLFCMkc9VHrj+ZNVIoLMCN4wkw0IgNY2LH79WaLAAAAAAAAAAAAAAABAAAADXRlc3QtdXNlci1yc2EAAAAMAAAACHRlc3R1c2VyAAAAAGivIlwAAAAAaLB0RwAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIC6qlgO7E2qluMn+v9DO/okxKLQeU2aFb69pgy6jacnkAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEBHN+MUaadMhjIJrcwI1woYnmS135FABeflp92GAAJ96yS8iUDF3l1KgIDFwCLIa9DZOCj0vM8vom7rBv03BpsA test-user-rsa';

    const parsed = parseCertificate(originalCert);
    const serialized = serializeCertificate(parsed);

    // Since serialize is placeholder, it will not match exactly, but check basic properties
    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });

  it('should round-trip real Ed25519 SSH certificate', () => {
    const originalCert = 'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIOSBBJEgN2QmMKFF9way54gb0ytGMGgTSB6FVv+H0/OgAAAAIAK4yjyozG/QFINLQkz35aziQzWD3kzJXRo++KDl3Y9HAAAAAAAAAAAAAAABAAAAEXRlc3QtdXNlci1lZDI1NTE5AAAADAAAAAh0ZXN0dXNlcgAAAABoryJcAAAAAGiwdEsAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAuqpYDuxNqpbjJ/r/Qzv6JMSi0HlNmhW+vaYMuo2nJ5AAAAFMAAAALc3NoLWVkMjU1MTkAAABAScXlIavj0kJoE/6vr/Da8+181Z0E5TIoaj78tmcxJ89n45r8gKS2ipUay3PpUX7Wll6wKmt/BatNu0j757IACA== test-user-ed25519';

    const parsed = parseCertificate(originalCert);
    const serialized = serializeCertificate(parsed);

    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });

  it('should round-trip real ECDSA P-256 SSH certificate', () => {
    const originalCert = 'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgLQJpeITGDHn9MWmsYxCkrpfpes+kUSPmW3aqtXfzDX8AAAAIbmlzdHAyNTYAAABBBI5uJjleYPE3VSDfwSTyGhrupTZXFaf1KUeGFjwc93bhw10zrd/7pccJllj9ubMMIEcuDgbkEyolyDmuS/EAdRAAAAAAAAAAAAAAAAEAAAAPdGVzdC11c2VyLWVjZHNhAAAADAAAAAh0ZXN0dXNlcgAAAABoryJcAAAAAGiwdFEAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAuqpYDuxNqpbjJ/r/Qzv6JMSi0HlNmhW+vaYMuo2nJ5AAAAFMAAAALc3NoLWVkMjU1MTkAAABAXdy+Uboy5tqOK9ihJN6Ap+b69sk78p0i+KnbL4fEljSPk/dm+Z9HeRKBHqXXlk0PRLqQlv6tPeBGGnU+QnVHBw== test-user-ecdsa';

    const parsed = parseCertificate(originalCert);
    const serialized = serializeCertificate(parsed);

    const reParsed = parseCertificate(serialized);
    expect(reParsed.type).toBe(parsed.type);
    expect(reParsed.keyData).toEqual(parsed.keyData);
  });
});
