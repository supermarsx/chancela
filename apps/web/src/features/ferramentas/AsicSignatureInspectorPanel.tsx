import { useRef, useState, type ReactNode } from 'react';
import type {
  AsicBlockerReport,
  AsicEmbeddedEvidenceBlockerReport,
  AsicEmbeddedEvidenceIndicatorReport,
  AsicInspectionFinding,
  AsicSignatureInspectionResponse,
  AsicTechnicalArchiveTimestampReport,
  AsicTechnicalSignatureReport,
} from '../../api/types';
import { useInspectAsicSignature } from '../../api/hooks';
import { t as translateNow, useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
} from '../../ui';

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  return hex(await globalThis.crypto.subtle.digest('SHA-256', buffer));
}

function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result);
        return;
      }
      reject(new Error('file read did not return bytes'));
    };
    reader.onerror = () => reject(reader.error ?? new Error('file read failed'));
    reader.readAsArrayBuffer(file);
  });
}

function formatBytes(value: number, t: TFunction): string {
  if (!Number.isFinite(value) || value < 0) return t('pdfValidator.size.unknown');
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${amount.toFixed(amount < 10 ? 1 : 0)} ${unit}`;
}

function boolText(value: boolean, t: TFunction): string {
  return value ? t('common.yes') : t('common.no');
}

function statusTone(value: boolean | string): 'neutral' | 'ok' | 'warn' | 'error' {
  if (value === true || value === 'valid' || value === 'available') return 'ok';
  if (value === false || value === 'invalid' || value === 'error') return 'error';
  const normalized = String(value).toLowerCase();
  if (normalized.includes('not_performed') || normalized.includes('not performed')) return 'warn';
  if (
    normalized.includes('false') ||
    normalized.includes('invalid') ||
    normalized.includes('fail')
  ) {
    return 'error';
  }
  if (normalized.includes('unsupported') || normalized.includes('gap')) return 'warn';
  return 'neutral';
}

function findingTone(severity: string): 'neutral' | 'warn' | 'error' {
  if (severity === 'error') return 'error';
  if (severity === 'warning') return 'warn';
  return 'neutral';
}

function resultLabel(report: AsicSignatureInspectionResponse, t: TFunction): string {
  return report.status === 'valid'
    ? t('pdfValidator.status.valid')
    : t('pdfValidator.status.invalid');
}

function KeyValueGrid({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="pdf-validator-kv">
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function TextList({ values, emptyLabel }: { values: string[]; emptyLabel: string }) {
  if (!values.length) return <span className="muted">{emptyLabel}</span>;
  return (
    <span className="pdf-validator-chipline">
      {values.map((value, index) => (
        <code className="mono pdf-validator-chip" key={`${value}-${index}`}>
          {value}
        </code>
      ))}
    </span>
  );
}

function DigestValue({ value }: { value: string | null }) {
  if (!value) return <span className="muted">-</span>;
  return <Digest value={value} />;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

function BlockerList({
  blockers,
  emptyLabel,
}: {
  blockers: (AsicBlockerReport | AsicEmbeddedEvidenceBlockerReport)[];
  emptyLabel: string;
}) {
  if (!blockers.length) return <p className="muted">{emptyLabel}</p>;
  return (
    <ul className="pdf-validator-findings">
      {blockers.map((blocker, index) => (
        <li
          key={`${'id' in blocker ? blocker.id : blocker.code}-${'member_path' in blocker ? blocker.member_path : blocker.source_path}-${index}`}
        >
          <Badge tone="warn">{'id' in blocker ? blocker.id : blocker.code}</Badge>
          <div>
            <code className="mono">
              {'member_path' in blocker
                ? (blocker.member_path ?? 'container')
                : blocker.source_path}
            </code>
            <p>{blocker.message}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function FindingsList({ findings }: { findings: AsicInspectionFinding[] }) {
  if (!findings.length)
    return (
      <p className="muted">
        {translateNow('uiLiteral.asicSignatureInspectorPanel.semOcorrenciasReportadas')}
      </p>
    );
  return (
    <ul className="pdf-validator-findings">
      {findings.map((finding) => (
        <li key={`${finding.severity}-${finding.code}-${finding.message}`}>
          <Badge tone={findingTone(finding.severity)}>{finding.severity}</Badge>
          <div>
            <code className="mono">{finding.code}</code>
            <p>{finding.message}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function EvidenceIndicatorList({
  indicators,
}: {
  indicators: AsicEmbeddedEvidenceIndicatorReport[];
}) {
  if (!indicators.length) {
    return (
      <p className="muted">
        {translateNow(
          'uiLiteral.asicSignatureInspectorPanel.semIndicadoresDeEvidenciaEmbebidaReportados',
        )}
      </p>
    );
  }
  return (
    <ul className="pdf-validator-findings">
      {indicators.map((indicator) => (
        <li key={`${indicator.code}-${indicator.source_path}-${indicator.evidence_kind}`}>
          <Badge tone="neutral">{indicator.evidence_kind}</Badge>
          <div>
            <code className="mono">{indicator.code}</code>
            <p>{indicator.message}</p>
            <p className="muted">{indicator.source_path}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function SignatureList({ signatures }: { signatures: AsicTechnicalSignatureReport[] }) {
  const t = useT();
  if (!signatures.length) {
    return (
      <EmptyState title={t('uiLiteral.asicSignatureInspectorPanel.semAssinaturasReconhecidas')}>
        <p>
          {t('uiLiteral.asicSignatureInspectorPanel.aInspecaoTecnicaNaoEncontrouMembrosCadesOu')}
        </p>
      </EmptyState>
    );
  }
  return (
    <ul className="pdf-validator-signatures">
      {signatures.map((signature) => (
        <li key={signature.path}>
          <div className="pdf-validator-evidence-head">
            <span>
              <Badge tone={statusTone(signature.valid)}>
                {signature.valid
                  ? t('pdfValidator.status.valid')
                  : t('pdfValidator.status.invalid')}
              </Badge>
              <code className="mono">{signature.path}</code>
            </span>
            <span className="muted">{signature.kind}</span>
          </div>
          <KeyValueGrid
            rows={[
              { label: 'Manifesto', value: signature.manifest_path ?? '-' },
              {
                label: 'Objetos cobertos',
                value: (
                  <TextList
                    values={signature.covered_data_objects}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'Certificado SHA-256',
                value: <DigestValue value={signature.signer_cert_sha256} />,
              },
              { label: 'Sujeito do certificado', value: signature.signer_cert_subject ?? '-' },
              { label: 'Hora de assinatura', value: signature.signing_time ?? '-' },
              { label: 'Nível XAdES', value: signature.xades_level ?? '-' },
              {
                label: 'Timestamp da assinatura',
                value: boolText(signature.has_signature_timestamp, t),
              },
              {
                label: 'Confiança do timestamp',
                value: (
                  <Badge tone={statusTone(signature.signature_timestamp_trust_validation)}>
                    {signature.signature_timestamp_trust_validation}
                  </Badge>
                ),
              },
              {
                label: 'Confiança',
                value: (
                  <Badge tone={statusTone(signature.trust_validation)}>
                    {signature.trust_validation}
                  </Badge>
                ),
              },
              {
                label: 'Revogação',
                value: (
                  <Badge tone={statusTone(signature.revocation_validation)}>
                    {signature.revocation_validation}
                  </Badge>
                ),
              },
              {
                label: 'Validação de prestador',
                value: (
                  <Badge tone={statusTone(signature.provider_validation)}>
                    {signature.provider_validation}
                  </Badge>
                ),
              },
              {
                label: 'Aprovação de prestador afirmada',
                value: boolText(signature.provider_approval_claimed, t),
              },
              {
                label: 'Validade legal afirmada',
                value: boolText(signature.legal_validity_claimed, t),
              },
              {
                label: 'Assinatura qualificada afirmada',
                value: boolText(signature.qualified_signature_claimed, t),
              },
              { label: 'QES afirmada', value: boolText(signature.qes_claimed, t) },
              {
                label: 'Motivos de falha',
                value: (
                  <TextList
                    values={signature.failure_reasons}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
            ]}
          />
        </li>
      ))}
    </ul>
  );
}

function ArchiveTimestampList({ archives }: { archives: AsicTechnicalArchiveTimestampReport[] }) {
  const t = useT();
  if (!archives.length)
    return (
      <p className="muted">
        {t('uiLiteral.asicSignatureInspectorPanel.semTimestampsDeArquivoAsicReportados')}
      </p>
    );
  return (
    <ul className="pdf-validator-timestamps">
      {archives.map((archive) => (
        <li key={`${archive.manifest_path}-${archive.timestamp_path}`}>
          <div className="pdf-validator-evidence-head">
            <span>
              <Badge tone={statusTone(archive.valid)}>
                {archive.valid ? t('pdfValidator.status.valid') : t('pdfValidator.status.invalid')}
              </Badge>
              <code className="mono">{archive.timestamp_path || 'timestamp sem caminho'}</code>
            </span>
            <span className="muted">{archive.manifest_path}</span>
          </div>
          <KeyValueGrid
            rows={[
              { label: 'Manifesto de arquivo', value: archive.manifest_path },
              { label: 'Timestamp de arquivo', value: archive.timestamp_path || '-' },
              {
                label: 'Imprint corresponde ao manifesto',
                value: boolText(archive.imprint_matches_manifest, t),
              },
              { label: 'Referências válidas', value: boolText(archive.references_valid, t) },
              {
                label: 'Membros cobertos',
                value: (
                  <TextList
                    values={archive.covered_members}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              { label: 'Hora no token', value: archive.gen_time ?? '-' },
              {
                label: 'Confiança do timestamp',
                value: (
                  <Badge tone={statusTone(archive.timestamp_trust_validation)}>
                    {archive.timestamp_trust_validation}
                  </Badge>
                ),
              },
              { label: 'B-LTA afirmado', value: boolText(archive.b_lta_claimed, t) },
              {
                label: 'Validade legal afirmada',
                value: boolText(archive.legal_validity_claimed, t),
              },
              {
                label: 'Motivos de falha',
                value: (
                  <TextList
                    values={archive.failure_reasons}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
            ]}
          />
        </li>
      ))}
    </ul>
  );
}

function AsicReport({ report }: { report: AsicSignatureInspectionResponse }) {
  const t = useT();
  const profile = report.profile;
  const technical = report.technical_validation;
  const embedded = technical.embedded_evidence;

  return (
    <div className="pdf-validator-report">
      <div className="pdf-validator-summary">
        <div>
          <p className="field__label">{t('uiLiteral.asicSignatureInspectorPanel.resultadoAsic')}</p>
          <h3>{report.filename ?? 'Contentor ASiC sem nome'}</h3>
          <p className="muted">{report.legal_notice}</p>
        </div>
        <Badge tone={statusTone(report.status)}>{resultLabel(report, t)}</Badge>
      </div>

      <KeyValueGrid
        rows={[
          { label: t('pdfValidator.field.size'), value: formatBytes(report.size_bytes, t) },
          { label: t('pdfValidator.field.sha256'), value: <Digest value={report.sha256} /> },
          {
            label: t('pdfValidator.field.declaredSize'),
            value:
              report.declared_size_bytes === null
                ? '-'
                : formatBytes(report.declared_size_bytes, t),
          },
          {
            label: t('pdfValidator.field.declaredSha256'),
            value: <DigestValue value={report.declared_sha256} />,
          },
          { label: 'Âmbito', value: report.scope },
        ]}
      />

      <div className="pdf-validator-details">
        <details open>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.perfilDoContentor')}</summary>
          <KeyValueGrid
            rows={[
              { label: 'Tipo ASiC', value: profile.container_kind },
              { label: 'Mimetype', value: profile.mimetype },
              { label: 'Perfil de assinatura', value: profile.signature_profile },
              { label: 'Forma do perfil', value: profile.profile_shape },
              { label: 'Perfil limitado', value: profile.bounded_profile ?? '-' },
              {
                label: 'Candidato suportado limitado',
                value: boolText(profile.bounded_supported_candidate, t),
              },
              {
                label: 'Validação XAdES executada',
                value: boolText(report.xades_validation_performed, t),
              },
              {
                label: 'Validação técnica executada',
                value: boolText(technical.validation_performed, t),
              },
              {
                label: 'Criptograficamente válido',
                value: boolText(technical.cryptographically_valid, t),
              },
              {
                label: 'Todas as assinaturas válidas',
                value: boolText(technical.all_signatures_valid, t),
              },
            ]}
          />
          <KeyValueGrid
            rows={[
              {
                label: 'Membros',
                value: (
                  <TextList
                    values={profile.member_paths.all}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'Payloads',
                value: (
                  <TextList
                    values={profile.member_paths.payloads}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'Manifestos',
                value: (
                  <TextList
                    values={profile.member_paths.manifests}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'Assinaturas CAdES',
                value: (
                  <TextList
                    values={profile.member_paths.cades_signatures}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'Assinaturas XAdES',
                value: (
                  <TextList
                    values={profile.member_paths.xades_signatures}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
              {
                label: 'META-INF não suportado',
                value: (
                  <TextList
                    values={profile.member_paths.unsupported_meta_inf}
                    emptyLabel={t('pdfValidator.value.none')}
                  />
                ),
              },
            ]}
          />
        </details>

        <details open>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.limitacoesExplicitas')}</summary>
          <KeyValueGrid
            rows={[
              {
                label: 'Validade legal afirmada',
                value: boolText(report.legal_validity_claimed, t),
              },
              {
                label: 'Assinatura qualificada afirmada',
                value: boolText(report.qualified_signature_claimed, t),
              },
              {
                label: 'Assinatura eletrónica qualificada afirmada',
                value: boolText(report.qualified_electronic_signature_claimed, t),
              },
              { label: 'QES afirmada', value: boolText(report.qes_claimed, t) },
              {
                label: 'Validação de confiança',
                value: (
                  <Badge tone={statusTone(report.trust_validation)}>
                    {report.trust_validation}
                  </Badge>
                ),
              },
              {
                label: 'Validação de âncora de confiança',
                value: (
                  <Badge tone={statusTone(report.trust_anchor_validation)}>
                    {report.trust_anchor_validation}
                  </Badge>
                ),
              },
              {
                label: 'Validação de revogação',
                value: (
                  <Badge tone={statusTone(report.revocation_validation)}>
                    {report.revocation_validation}
                  </Badge>
                ),
              },
              { label: 'Chamadas a prestador', value: boolText(report.live_provider_calls, t) },
              { label: 'TSL ao vivo', value: boolText(report.live_tsl_fetching, t) },
              { label: 'TSA ao vivo', value: boolText(report.live_tsa_fetching, t) },
              { label: 'OCSP ao vivo', value: boolText(report.live_ocsp_fetching, t) },
              { label: 'CRL ao vivo', value: boolText(report.live_crl_fetching, t) },
              {
                label: 'Aprovação de prestador afirmada',
                value: boolText(report.provider_approval_claimed, t),
              },
              { label: 'B-LT afirmado', value: boolText(report.b_lt_claimed, t) },
              { label: 'B-LTA afirmado', value: boolText(report.b_lta_claimed, t) },
              { label: 'LTV afirmado', value: boolText(report.ltv_claimed, t) },
              {
                label: 'Conformidade ASiC de produção afirmada',
                value: boolText(report.production_asic_compliance_claimed, t),
              },
              {
                label: 'Conformidade XAdES de produção afirmada',
                value: boolText(report.production_xades_conformance_claimed, t),
              },
              {
                label: 'Efeito legal eIDAS afirmado',
                value: boolText(report.eidas_legal_effect_claimed, t),
              },
              { label: 'Assinatura executada', value: boolText(report.signing_performed, t) },
              {
                label: 'Mutação de armazenamento',
                value: boolText(report.storage_mutation_performed, t),
              },
              {
                label: 'Mutação de arquivo',
                value: boolText(report.archive_mutation_performed, t),
              },
            ]}
          />
        </details>

        <details open>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.assinaturasTecnicas')}</summary>
          <SignatureList signatures={technical.signatures} />
        </details>

        <details open>
          <summary>
            {t('uiLiteral.asicSignatureInspectorPanel.evidenciaEmbebidaEBloqueadores')}
          </summary>
          <KeyValueGrid
            rows={[
              { label: 'Âmbito da evidência', value: embedded.evidence_scope },
              {
                label: 'Confiança',
                value: (
                  <Badge tone={statusTone(embedded.trust_validation)}>
                    {embedded.trust_validation}
                  </Badge>
                ),
              },
              {
                label: 'Revogação',
                value: (
                  <Badge tone={statusTone(embedded.revocation_validation)}>
                    {embedded.revocation_validation}
                  </Badge>
                ),
              },
              {
                label: 'Confiança do timestamp',
                value: (
                  <Badge tone={statusTone(embedded.timestamp_trust_validation)}>
                    {embedded.timestamp_trust_validation}
                  </Badge>
                ),
              },
              { label: 'TSL ao vivo', value: boolText(embedded.live_tsl_fetching, t) },
              { label: 'TSA ao vivo', value: boolText(embedded.live_tsa_fetching, t) },
              { label: 'OCSP ao vivo', value: boolText(embedded.live_ocsp_fetching, t) },
              { label: 'CRL ao vivo', value: boolText(embedded.live_crl_fetching, t) },
              { label: 'B-LT afirmado', value: boolText(embedded.b_lt_claimed, t) },
              { label: 'B-LTA afirmado', value: boolText(embedded.b_lta_claimed, t) },
              { label: 'LTV afirmado', value: boolText(embedded.ltv_claimed, t) },
              {
                label: 'Validade legal afirmada',
                value: boolText(embedded.legal_validity_claimed, t),
              },
              {
                label: 'Assinatura qualificada afirmada',
                value: boolText(embedded.qualified_signature_claimed, t),
              },
            ]}
          />
          <h4>{t('uiLiteral.asicSignatureInspectorPanel.indicadores')}</h4>
          <EvidenceIndicatorList indicators={embedded.indicators} />
          <h4>{t('uiLiteral.asicSignatureInspectorPanel.bloqueadores')}</h4>
          <BlockerList
            blockers={embedded.blockers}
            emptyLabel="Sem bloqueadores de evidência embebida reportados."
          />
        </details>

        <details open>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.timestampsDeArquivo')}</summary>
          <ArchiveTimestampList archives={technical.archive_timestamps} />
        </details>

        {report.cades ? (
          <details>
            <summary>{t('uiLiteral.asicSignatureInspectorPanel.validacaoCadesLimitada')}</summary>
            <KeyValueGrid
              rows={[
                {
                  label: 'Estado',
                  value: (
                    <Badge tone={statusTone(report.cades.status)}>{report.cades.status}</Badge>
                  ),
                },
                {
                  label: 'Validação executada',
                  value: boolText(report.cades.validation_performed, t),
                },
                {
                  label: 'Criptograficamente válido',
                  value: boolText(report.cades.cryptographically_valid, t),
                },
                { label: 'Erro', value: report.cades.validation_error ?? '-' },
                { label: 'Conteúdo assinado', value: report.cades.signed_content.kind },
                { label: 'Membro assinado', value: report.cades.signed_content.member_path || '-' },
                {
                  label: 'Digest do conteúdo',
                  value: <DigestValue value={report.cades.signed_content.sha256} />,
                },
                {
                  label: 'Certificado SHA-256',
                  value: <DigestValue value={report.cades.signer_cert_sha256} />,
                },
                { label: 'Sujeito do certificado', value: report.cades.signer_cert_subject ?? '-' },
                { label: 'Hora de assinatura', value: report.cades.signing_time ?? '-' },
                {
                  label: 'Timestamp da assinatura',
                  value: boolText(report.cades.has_signature_timestamp, t),
                },
                { label: 'Âmbito', value: report.cades.evidence_scope },
                {
                  label: 'Confiança',
                  value: (
                    <Badge tone={statusTone(report.cades.trust_validation)}>
                      {report.cades.trust_validation}
                    </Badge>
                  ),
                },
                {
                  label: 'Revogação',
                  value: (
                    <Badge tone={statusTone(report.cades.revocation_validation)}>
                      {report.cades.revocation_validation}
                    </Badge>
                  ),
                },
                {
                  label: 'Validade legal afirmada',
                  value: boolText(report.cades.legal_validity_claimed, t),
                },
                {
                  label: 'Assinatura qualificada afirmada',
                  value: boolText(report.cades.qualified_signature_claimed, t),
                },
              ]}
            />
          </details>
        ) : null}

        <details>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.diagnosticoDeManifestos')}</summary>
          {profile.manifest_diagnostics.length ? (
            <ul className="pdf-validator-signatures">
              {profile.manifest_diagnostics.map((manifest) => (
                <li key={manifest.path}>
                  <div className="pdf-validator-evidence-head">
                    <span>
                      <Badge tone="neutral">
                        {translateNow('uiLiteral.asicSignatureInspectorPanel.manifesto')}
                      </Badge>
                      <code className="mono">{manifest.path}</code>
                    </span>
                    <span className="muted">{formatBytes(manifest.size, t)}</span>
                  </div>
                  <KeyValueGrid
                    rows={[
                      {
                        label: 'Referências de assinatura',
                        value: (
                          <TextList
                            values={manifest.signature_references.map(
                              (ref) =>
                                `${ref.uri} (${ref.member_present ? 'presente' : 'ausente'}${ref.member_kind ? `, ${ref.member_kind}` : ''})`,
                            )}
                            emptyLabel={t('pdfValidator.value.none')}
                          />
                        ),
                      },
                      {
                        label: 'Referências de dados',
                        value: (
                          <TextList
                            values={manifest.data_object_references.map(
                              (ref) =>
                                `${ref.uri} (${ref.payload_present ? 'presente' : 'ausente'}, digest=${ref.digest_matches === null ? 'n/a' : ref.digest_matches})`,
                            )}
                            emptyLabel={t('pdfValidator.value.none')}
                          />
                        ),
                      },
                    ]}
                  />
                  <BlockerList blockers={manifest.blockers} emptyLabel="Sem bloqueadores." />
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              {t('uiLiteral.asicSignatureInspectorPanel.semDiagnosticosDeManifestoReportados')}
            </p>
          )}
        </details>

        <details>
          <summary>
            {t('uiLiteral.asicSignatureInspectorPanel.bloqueadoresEDiagnosticosDeAssinatura')}
          </summary>
          <BlockerList blockers={profile.blockers} emptyLabel="Sem bloqueadores de perfil." />
          {profile.signature_diagnostics.length ? (
            <ul className="pdf-validator-signatures">
              {profile.signature_diagnostics.map((signature) => (
                <li key={signature.path}>
                  <div className="pdf-validator-evidence-head">
                    <span>
                      <Badge tone="neutral">{signature.member_kind}</Badge>
                      <code className="mono">{signature.path}</code>
                    </span>
                    <span className="muted">{formatBytes(signature.size, t)}</span>
                  </div>
                  <KeyValueGrid
                    rows={[
                      {
                        label: 'Referenciado por manifestos',
                        value: (
                          <TextList
                            values={signature.referenced_by_manifest_paths}
                            emptyLabel={t('pdfValidator.value.none')}
                          />
                        ),
                      },
                    ]}
                  />
                  <BlockerList blockers={signature.blockers} emptyLabel="Sem bloqueadores." />
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              {t('uiLiteral.asicSignatureInspectorPanel.semDiagnosticosDeAssinaturaReportados')}
            </p>
          )}
        </details>

        <details open>
          <summary>{t('uiLiteral.asicSignatureInspectorPanel.ocorrencias')}</summary>
          <FindingsList findings={report.findings} />
        </details>
      </div>
    </div>
  );
}

export function AsicSignatureInspectorPanel() {
  const t = useT();
  const inspect = useInspectAsicSignature();
  const [file, setFile] = useState<File | null>(null);
  const [readError, setReadError] = useState<Error | null>(null);
  const [inspectError, setInspectError] = useState<{ requestId: number; error: Error } | null>(
    null,
  );
  const [report, setReport] = useState<{
    requestId: number;
    report: AsicSignatureInspectionResponse;
  } | null>(null);
  const [pendingRequestId, setPendingRequestId] = useState<number | null>(null);
  const requestIdRef = useRef(0);

  async function submit() {
    if (!file) return;
    const submittedFile = file;
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    setReadError(null);
    setInspectError(null);
    setReport(null);
    setPendingRequestId(requestId);
    inspect.reset();

    const isCurrentRequest = () => requestIdRef.current === requestId;

    let mutationStarted = false;
    try {
      const buffer = await readFileAsArrayBuffer(submittedFile);
      const declaredSha256 = await sha256Hex(buffer);
      if (!isCurrentRequest()) return;
      mutationStarted = true;
      const nextReport = await inspect.mutateAsync({
        content_base64: arrayBufferToBase64(buffer),
        filename: submittedFile.name,
        declared_sha256: declaredSha256,
        declared_size_bytes: submittedFile.size,
      });
      if (isCurrentRequest()) {
        setReport({ requestId, report: nextReport });
      }
    } catch (e) {
      if (!isCurrentRequest()) return;
      if (mutationStarted) {
        setInspectError({ requestId, error: toError(e) });
      } else {
        setReadError(toError(e));
      }
    } finally {
      if (isCurrentRequest()) {
        setPendingRequestId(null);
      }
    }
  }

  const currentReport = report?.requestId === requestIdRef.current ? report.report : null;
  const currentInspectError =
    inspectError?.requestId === requestIdRef.current ? inspectError.error : null;
  const isInspecting = pendingRequestId === requestIdRef.current;

  return (
    <Card
      title={t('uiLiteral.asicSignatureInspectorPanel.inspetorTecnicoAsic')}
      actions={
        <Button
          type="button"
          variant="primary"
          icon={<Icon.Archive />}
          disabled={!file || isInspecting}
          onClick={() => void submit()}
        >
          {isInspecting ? 'A inspecionar...' : 'Inspecionar ASiC'}
        </Button>
      }
    >
      <div className="pdf-validator stack">
        <InlineWarning
          tone="info"
          title={t('uiLiteral.asicSignatureInspectorPanel.inspecaoTecnicaLocal')}
        >
          {' '}
          {t(
            'uiLiteral.asicSignatureInspectorPanel.leiaApenasContentoresLocaisAsiceSceZipNao',
          )}{' '}
        </InlineWarning>

        <div className="pdf-validator-upload">
          <Field
            label={t('uiLiteral.asicSignatureInspectorPanel.contentorAsic')}
            htmlFor="asic-signature-inspector-file"
            hint={
              file ? `Selecionado: ${file.name}` : 'Selecione um contentor .asice, .sce ou ZIP.'
            }
          >
            <input
              id="asic-signature-inspector-file"
              className="control"
              type="file"
              accept=".asice,.sce,.zip,application/zip,application/vnd.etsi.asic-e+zip,application/vnd.etsi.asic-s+zip"
              onChange={(e) => {
                requestIdRef.current += 1;
                setFile(e.currentTarget.files?.[0] ?? null);
                inspect.reset();
                setReadError(null);
                setInspectError(null);
                setReport(null);
                setPendingRequestId(null);
              }}
            />
          </Field>
          {file ? (
            <div className="pdf-validator-file">
              <Badge tone="neutral">ASiC</Badge>
              <span>{file.name}</span>
              <span className="muted">{formatBytes(file.size, t)}</span>
            </div>
          ) : null}
        </div>

        {isInspecting ? (
          <p className="pdf-validator-status" aria-live="polite">
            {' '}
            {t('uiLiteral.asicSignatureInspectorPanel.aInspecionarContentorAsicLocal')}{' '}
          </p>
        ) : null}
        {readError ? <ErrorNote error={readError} /> : null}
        {currentInspectError ? (
          <InlineWarning tone="error" title={t('pdfValidator.failClosed.title')}>
            <p>
              {' '}
              {t(
                'uiLiteral.asicSignatureInspectorPanel.oEndpointRecusouAInspecaoNenhumArtefactoFoi',
              )}{' '}
            </p>
            <ErrorNote error={currentInspectError} />
          </InlineWarning>
        ) : null}
        {currentReport ? <AsicReport report={currentReport} /> : null}
      </div>
    </Card>
  );
}
