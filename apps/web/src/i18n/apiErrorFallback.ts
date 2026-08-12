/**
 * API ERROR COPY (t58-e5) — the pt-PT sentence a person reads when a request fails.
 *
 * The server answers a failing request with `{"error": "<English operator detail>", "code":
 * "<stable snake_case identifier>", …}`. The English `error` string stays on the wire and stays
 * authoritative: it is what the Rust tests assert on, what the server logs, and what an operator
 * quotes in a bug report. This module does NOT replace it — it **demotes** it. The `code` resolves
 * to a pt-PT sentence that becomes the headline; the English detail moves into the technical-details
 * block, alongside the code, the HTTP status and the request id. Nothing the server said is dropped
 * (memory: `reject-never-silently-transform`).
 *
 * **Why this module is self-contained, not folded into the catalogs.** `Catalog` is a total type
 * (`Record<MessageKey, string>` over all 14 locales), so a key added to one locale is a `TS2741` on
 * the other thirteen at once. This lane adds ~100 keys, i.e. ~1,400 edits to files nine live lanes
 * are serialised on. It therefore follows the established escape hatch — `actBodyFallback.ts`,
 * `actLifecycleFallback.ts`, `notificationsRetentionFallback.ts` and ~20 siblings: a pt-PT source
 * object plus an English fallback that `satisfies` the same key set, resolved through its own
 * locale-aware hook. Nothing in the shared catalog moves and the catalog-leak / literal-copy gates
 * never see these strings; `apiErrorFallback.test.ts` gates them instead.
 *
 * ─── THE BINDING AUTHORING RULE ────────────────────────────────────────────────────────────────
 *
 * **A noun never enters a sentence through a placeholder. If the copy varies by noun, it varies by
 * key.** Portuguese agreement breaks the moment a noun arrives at runtime — the article, any
 * adjective and any past participle all inflect for its gender and number:
 *
 *   ✗ `'Não foi possível eliminar o {entity}.'`   → «o ata» / «o entidade» / «o atas»
 *   ✓ `'not_found.act'`:  'A ata indicada não existe.'
 *   ✓ `'not_found.book'`: 'O livro indicado não existe.'
 *
 * So the server emits `already_exists.book`, never `already_exists` + `{resource: "book"}`. The noun
 * lives in the code. This also makes the codes more useful to an operator reading a log.
 *
 * The only values that may be interpolated are **agreement-inert**: integers. Seconds are rendered
 * against the symbol `s` (`'{seconds} s'`, matching the server's own convention) precisely so that
 * `1` does not have to agree with a spelled-out «segundo/segundos». `apiErrorFallback.test.ts`
 * enforces the allowlist; a placeholder that is not on it fails the build.
 *
 * ─── DELIBERATE REFUSALS ───────────────────────────────────────────────────────────────────────
 *
 * {@link NON_ROUTINE_CODES} lists the surfaces that are fail-closed by design. Their copy says
 * «recusado», not «falhou», and states that repeating the operation will not help. Localising a
 * refusal must not make it read as a transient hiccup the operator should retry past.
 *
 * The cross-user 403 (`cross_user_proof_required`) is a **security** constraint, not just a copy
 * one: the server answers wrong-password, absent-proof and non-existent-target with one identical
 * response so it never enumerates users. The copy therefore says so explicitly and must never be
 * "helpfully" split into finer cases — that would reintroduce the enumeration through the copy.
 *
 * ─── CONVENTIONS ───────────────────────────────────────────────────────────────────────────────
 *
 * Codes, identifiers and the wire `error` string stay ENGLISH — they are identifiers, not copy.
 * pt-PT is the source; English is the fallback the other 13 locales get. No invented anglicisms
 * (memory: `pt-pt-no-invented-anglicisms`) — a concept with no genuine pt-PT term is escalated, not
 * coined. No evidentiary claim in any string (memory: `tagline-no-valor-probatorio`).
 *
 * The four `InvalidActBody` sub-codes appear here as full sentences for the app-wide error surface;
 * `actBodyFallback.ts` keeps its own short noun phrases for the in-editor diagnostic chip. Both are
 * correct for their surface and neither is a duplicate of the other.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

/**
 * pt-PT source copy. One key per server `code`, plus the always-present `apiError.tier.<status>`
 * headlines that guarantee no status is ever left without a sentence.
 */
export const apiErrorPtPT = {
  // ═══ STATUS TIERS ═════════════════════════════════════════════════════════════════════════
  // Always present, for any code the catalog does not (yet) know. Honest about the status and
  // nothing more — the server's own detail is never dropped, it is shown in the details block.
  'apiError.tier.400': 'O pedido não foi aceite tal como foi enviado.',
  'apiError.tier.401': 'Não foi possível confirmar a sua identidade para esta operação.',
  'apiError.tier.403': 'Não tem autorização para esta operação.',
  'apiError.tier.404': 'Não foi encontrado o que pediu.',
  'apiError.tier.409': 'A operação foi recusada porque o estado atual não a permite.',
  'apiError.tier.410': 'O que pediu já não está disponível.',
  'apiError.tier.422': 'O pedido não pôde ser processado tal como foi enviado.',
  'apiError.tier.429': 'Foram feitos pedidos a mais. Aguarde antes de tentar de novo.',
  'apiError.tier.500': 'Ocorreu uma falha interna no servidor.',
  'apiError.tier.502': 'Um serviço externo não respondeu como esperado.',
  'apiError.tier.503':
    'O serviço está indisponível neste momento. Volte a tentar dentro de momentos.',
  'apiError.tier.unknown': 'A operação não foi concluída.',

  // ═══ DELIBERATE REFUSALS — must never read as routine or retryable ═══════════════════════

  // — Compliance (422) — cites each blocking issue individually, below this headline —————————
  'apiError.compliance_blocked':
    'A selagem foi recusada: há requisitos de conformidade por cumprir. Cada requisito em falta está indicado abaixo, com a base legal respetiva. Corrija-os e volte a submeter.',
  // — Unacknowledged warnings (409) — an acknowledgement prompt, not a dismissable notice ————
  'apiError.warnings_not_acknowledged':
    'A selagem não avança sem que confirme os avisos indicados abaixo. Leia cada um e confirme-o expressamente; fechar este aviso não os dá por confirmados.',

  // — Rejected ata body (422) — nothing is silently converted or dropped ————————————————————
  'apiError.invalid_act_body':
    'O texto da ata foi recusado e nada foi guardado. O ponto em causa está assinalado no editor.',
  'apiError.unsupported_markdown':
    'O texto da ata usa formatação que o documento não consegue representar. Nada foi convertido nem removido — corrija o ponto assinalado e volte a guardar.',
  'apiError.invalid_placeholder':
    'O texto da ata tem um campo de preenchimento mal escrito. Corrija o ponto assinalado e volte a guardar.',
  'apiError.body_too_large':
    'O texto da ata ultrapassa o tamanho máximo aceite. Reduza-o e volte a guardar.',
  'apiError.body_block_too_large':
    'Um dos parágrafos da ata ultrapassa o tamanho máximo aceite. Divida-o e volte a guardar.',

  // — Termo de encerramento, close-time refusals (409) ——————————————————————————————————————
  // Three distinct causes, three sentences. Each states only what has been established: a signed
  // document that contradicts the livro must not be sealed, but naming the wrong cause sends the
  // operator hunting a change that never happened.
  'apiError.termo_stale_facts':
    'O livro mudou depois de este termo de encerramento ter sido congelado para assinatura: os números declarados no termo assinado já não correspondem ao livro. Selá-lo faria com que o documento assinado contradissesse o registo, por isso foi recusado. Prepare de novo o termo de encerramento com os dados atualizados.',
  'apiError.termo_snapshot_render_drift':
    'O documento do termo de encerramento já não corresponde ao que foi assinado, embora os números declarados continuem certos. O que mudou foi a composição do documento, não os dados do livro. Selar um documento diferente daquele que foi assinado não é permitido, por isso o pedido foi recusado. Prepare de novo o termo de encerramento.',
  'apiError.termo_snapshot_mismatch':
    'O documento do termo de encerramento já não corresponde ao que foi assinado. Não foi possível apurar em que ponto divergiu, e um termo assinado que não corresponde ao livro não pode ser selado. Prepare de novo o termo de encerramento.',
  'apiError.termo_encerramento_not_signed':
    'O livro não foi encerrado: falta a assinatura digital de pelo menos um signatário obrigatório do termo de encerramento. Esta é uma recusa, não uma falha passageira — repetir a operação não a resolve.',

  // — Termo, freeze-time drift between the seeded text and the model it would be frozen against
  // (422). Recusa, mas resolúvel: rever e guardar as cláusulas no editor limpa-a, e por isso a copy
  // diz o que fazer em vez de dizer que repetir não ajuda.
  'apiError.termo_seed_template_drift':
    'Este termo ainda tem cláusulas com o texto de uma versão anterior do modelo, mas seria congelado contra a versão atual, que já não inclui esse texto. Reveja as cláusulas do termo e guarde-as antes de o congelar para assinatura.',

  // — Termo de abertura, open-time fail-closed refusal (409) ————————————————————————————————
  'apiError.termo_abertura_not_signed':
    'O livro não foi aberto: o termo de abertura ainda não tem assinatura digital de todos os signatários obrigatórios. Esta é uma recusa deliberada, não uma falha passageira — repetir a operação não a resolve. Cada signatário obrigatório tem de assinar digitalmente o termo antes de o livro poder abrir.',

  // — Cartão de Cidadão PIN (422) — «blocked» is terminal, never retryable —————————————————
  'apiError.cc_pin_blocked':
    'O PIN do Cartão de Cidadão está bloqueado após tentativas incorretas a mais. O cartão não volta a assinar enquanto estiver bloqueado: desbloqueie-o com o PUK na aplicação Autenticação.gov.',
  'apiError.cc_pin_wrong':
    'O PIN do Cartão de Cidadão está incorreto. Confirme-o e tente novamente.',
  'apiError.cc_pin_wrong.low':
    'O PIN do Cartão de Cidadão está incorreto. Restam poucas tentativas antes de o cartão bloquear.',
  'apiError.cc_pin_wrong.final_try':
    'O PIN do Cartão de Cidadão está incorreto e resta uma única tentativa. Se falhar outra vez, o cartão fica bloqueado e só o PUK o desbloqueia.',
  'apiError.cc_pin_wrong.locked':
    'O PIN do Cartão de Cidadão estava incorreto e o cartão ficou bloqueado. Desbloqueie-o com o PUK na aplicação Autenticação.gov.',

  // — Throttling (429) — honest about how long, because a real wait is real information ————
  'apiError.signin_throttled':
    'Tentativas de início de sessão a mais nesta conta. Aguarde {seconds} s antes de tentar de novo. Este limite protege a conta contra tentativas repetidas.',
  'apiError.signin_throttled.no_wait':
    'Tentativas de início de sessão a mais nesta conta. Aguarde e tente novamente mais tarde. Este limite protege a conta contra tentativas repetidas.',
  'apiError.credential_proof_throttled':
    'Tentativas a mais com a palavra-passe atual. Aguarde {seconds} s antes de tentar de novo.',
  'apiError.api_key_rate_limited':
    'A chave API excedeu o limite de pedidos. Aguarde {seconds} s antes de repetir o pedido.',

  // — Cluster write unavailability (503) — genuinely retryable, and says so ————————————————
  'apiError.cluster_not_leader':
    'Este nó não está a aceitar escritas neste momento: o conjunto de servidores está a eleger o nó responsável pelas escritas. A operação não foi realizada. Volte a tentar dentro de segundos — assim que a eleição terminar, o pedido passa.',
  'apiError.shared_sessions_unavailable':
    'Não foi possível contactar o serviço de sessões partilhadas, por isso a operação foi cancelada sem alterar nada. Volte a tentar dentro de momentos.',

  // — Cross-user credential change (403) — ONE answer for every no-valid-proof case ————————
  // Deliberately does not distinguish wrong password / absent proof / non-existent target: finer
  // copy here reintroduces user enumeration. Do not split this key.
  'apiError.cross_user_proof_required':
    'Alterar as credenciais de outro utilizador exige a palavra-passe atual desse utilizador ou uma frase de recuperação válida. O pedido foi recusado. Por segurança, a resposta é a mesma quer a prova esteja errada, esteja em falta, ou a conta indicada não exista — não confirma nem desmente a existência de qualquer conta.',
  'apiError.cross_user_recovery_cannot_generate_key':
    'Não é possível gerar uma chave de atestação apenas com a frase de recuperação: a chave é protegida pela palavra-passe atual do utilizador, que tem de ser fornecida.',

  // — Trust anchors (422) — THREE causes that must never share one sentence ————————————————
  // Key names mirror the server's `SigningError` variants exactly, so the two sides share one
  // vocabulary. Nothing configured, the wrong anchor configured, and the signer's own service being
  // inactive are three different problems with three different remedies — and only the third is
  // about the signer at all. Collapsing any two of them re-creates the misdirection that sent
  // operators to diagnose a third party for their own configuration.
  'apiError.trust_anchor_not_configured':
    'A assinatura qualificada foi recusada porque este servidor ainda não tem âncoras de confiança configuradas. Sem elas nenhum certificado pode ser dado como fiável. Configure a Lista de Confiança nas definições antes de voltar a assinar.',
  'apiError.trusted_list_not_anchored':
    'A assinatura qualificada foi recusada porque a Lista de Confiança não foi autenticada pela âncora de confiança configurada. A âncora pode não corresponder a esta lista, ou ter sido substituída por uma rotação de chaves cujo novo certificado ainda não está configurado. Verifique a âncora nas definições: o problema está deste lado, não no prestador do signatário.',
  'apiError.signer_service_not_active':
    'A assinatura qualificada foi recusada porque o prestador de serviços de confiança do signatário não consta como ativo na Lista de Confiança. O problema está do lado do prestador, não deste servidor.',

  // ═══ FALHAS DE ASSINATURA, POR CAUSA (`SigningError::code()`) ══════════════════════════════
  // The four `SigningError` → `ApiError` mappers used to sweep everything they did not name into
  // one `502` / «erro de gateway», with the only useful sentence written to the server log. These
  // are the causes that were behind it. `apiErrorFallback.test.ts` reads the closed code list out
  // of `crates/chancela-signing/src/lib.rs` and fails if one is left without copy here.
  //
  // The first sentence of each says WHERE the fault is, because that is the whole point of
  // splitting them: a Lista de Confiança that could not be fetched, our own PDF assembler, and a
  // profile this build never implemented send the operator to three different places.
  'apiError.signing_trusted_list_unavailable':
    'A assinatura não avançou porque não foi possível obter nem ler a Lista de Confiança. Sem ela não há veredito nenhum sobre o certificado do signatário: o que falhou foi o acesso à lista, não o certificado. Verifique o endereço da Lista de Confiança nas definições de assinatura e a ligação de saída deste servidor.',
  'apiError.signing_trusted_list_tls_chain_incomplete':
    'A assinatura não avançou porque o servidor que aloja a Lista de Confiança não enviou a cadeia completa do seu certificado: falta o certificado intermédio que liga o certificado desse servidor a uma raiz reconhecida. A falha está desse lado, não neste: o endereço está correto e a ligação chegou lá. Um navegador ou o curl podem abrir o mesmo endereço sem erro, porque procuram sozinhos os certificados em falta e este cliente não o faz. Indique o certificado intermédio em falta nas definições de assinatura, em signing.tls_intermediate_certs.',
  'apiError.signing_timestamp_failed':
    'A autoridade de carimbo temporal não devolveu um carimbo utilizável, por isso a assinatura não foi concluída. Verifique o endereço do serviço de carimbo temporal nas definições de assinatura e volte a tentar.',
  'apiError.signing_not_implemented':
    'A operação de assinatura pedida não está implementada nesta versão. Não é uma falha passageira — repetir não altera o resultado. Escolha um formato ou perfil que esta instalação produza; os detalhes técnicos indicam o que foi pedido.',
  'apiError.signing_unsupported_format':
    'Esta instalação não produz o formato de assinatura pedido. Repetir não altera o resultado: escolha um dos formatos suportados. Os detalhes técnicos indicam qual foi pedido.',
  'apiError.signing_unsupported_profile':
    'O perfil de assinatura pedido é reconhecido mas não é suportado por esta instalação. Repetir não altera o resultado. Os detalhes técnicos indicam o perfil em causa e as alternativas disponíveis.',
  'apiError.signing_format_input_mismatch':
    'O documento enviado não corresponde ao formato de assinatura pedido — uma assinatura PAdES, por exemplo, exige os bytes de um PDF. Os detalhes técnicos indicam o formato esperado.',
  'apiError.signing_family_mismatch':
    'O prestador escolhido não pertence à família de assinatura que este lugar de assinatura exige. Escolha um prestador da família pedida; os detalhes técnicos indicam as duas.',
  'apiError.signing_issuer_certificate_missing':
    'Não foi possível obter o certificado da entidade que emitiu o certificado do signatário, pelo que a verificação na Lista de Confiança não pôde ser feita. Uma assinatura qualificada não dispensa essa verificação, por isso o pedido foi recusado.',
  'apiError.signing_cades_failed':
    'Não foi possível montar ou validar a estrutura criptográfica CAdES/CMS da assinatura. A falha é deste servidor, não de um serviço externo; os detalhes técnicos indicam o componente em causa.',
  'apiError.signing_pades_failed':
    'Não foi possível assinar ou validar o PDF na estrutura PAdES. A falha é deste servidor, não de um serviço externo; os detalhes técnicos indicam o componente em causa.',
  'apiError.signing_asic_failed':
    'Não foi possível criar, ler ou validar o contentor ASiC. A falha é deste servidor, não de um serviço externo; os detalhes técnicos indicam o componente em causa.',
  'apiError.signing_xades_failed':
    'Não foi possível montar ou validar a assinatura XAdES/XMLDSig. A falha é deste servidor, não de um serviço externo; os detalhes técnicos indicam o componente em causa.',
  'apiError.signing_slot_out_of_range':
    'O lugar de assinatura indicado não existe neste conjunto de assinaturas. Recarregue a página e escolha um dos lugares disponíveis.',
  'apiError.signing_slot_already_signed':
    'Este lugar de assinatura já foi assinado, por isso não pode ser assinado outra vez. Nada foi alterado.',
  'apiError.signing_slot_out_of_order':
    'Este conjunto de assinaturas é sequencial e ainda falta assinar um lugar anterior. Assine primeiro o lugar em falta; os detalhes técnicos indicam qual.',
  'apiError.signing_wrong_path':
    'Este lugar de assinatura não pode ser assinado por esta via: uma assinatura manuscrita digitalizada e uma assinatura qualificada seguem percursos diferentes. Use o percurso correspondente à família deste lugar.',

  // ═══ SESSION AND CREDENTIALS ═════════════════════════════════════════════════════════════
  'apiError.session_required':
    'Esta operação exige sessão iniciada. Inicie sessão e tente de novo.',
  'apiError.session_invalid': 'A sessão terminou ou deixou de ser válida. Inicie sessão de novo.',
  'apiError.session_without_active_user': 'A sessão não está associada a nenhum utilizador ativo.',
  'apiError.invalid_credentials': 'As credenciais indicadas estão incorretas.',
  'apiError.current_password_incorrect': 'A palavra-passe atual está incorreta.',
  'apiError.two_factor_challenge_invalid':
    'O código de segundo fator está incorreto ou já expirou. Peça um novo e tente de novo.',
  'apiError.pairing_code_invalid':
    'O código de emparelhamento está incorreto ou já expirou. Gere um código novo.',
  'apiError.session_or_api_key_not_both':
    'Envie sessão ou chave API, nunca as duas no mesmo pedido.',
  'apiError.api_key_no_interactive_session':
    'Uma chave API não abre sessão interativa. Use as credenciais de um utilizador para esta operação.',
  'apiError.invite_invalid_or_expired': 'O convite é inválido ou já expirou. Peça um convite novo.',
  'apiError.delegation_refused':
    'A delegação foi recusada por inteiro. Nenhuma das autorizações pedidas foi atribuída.',
  'apiError.password_policy':
    'A palavra-passe não cumpre os requisitos de segurança. Os requisitos por cumprir estão indicados abaixo.',

  // — The account-lifecycle wall (409) — a refusal, never a lockout ————————————————————————————
  // The server refuses the *operation* and changes nothing; the account is exactly as it was. Its
  // detail names which credentials would have been left, in a list after a colon — the noun never
  // enters a sentence, here or there. Neither may read as retryable: repeating the removal without
  // first establishing another credential fails identically.
  'apiError.account_would_have_no_sign_in_credential':
    'A operação foi recusada: deixaria esta conta sem qualquer credencial com que iniciar sessão, e ninguém poderia voltar a entrar nela. Nada foi alterado. Estabeleça outra forma de iniciar sessão antes de remover esta; repetir a operação não a resolve. Os detalhes técnicos indicam o que ficaria na conta.',
  'apiError.account_would_have_no_recovery_credential':
    'A operação foi recusada: removeria uma forma de iniciar sessão sem que a conta ficasse com forma de ser recuperada, e perder a credencial que resta deixaria a conta inacessível. Nada foi alterado. Emita uma frase de recuperação antes de remover esta credencial; repetir a operação não a resolve. Os detalhes técnicos indicam o que ficaria na conta.',
  // The key-custody clause. The palavra-passe protects the attestation key even on an account that
  // signs in with a chave de acesso, so it is refused as a *wrap*, not as a sign-in credential —
  // and the copy has to say that, or the refusal reads as arbitrary to someone who has just been
  // told they no longer need to type it.
  'apiError.account_attestation_key_would_have_no_wrap':
    'A operação foi recusada: a chave de assinatura desta conta deixaria de ter uma proteção que se possa abrir, e a conta não voltaria a poder assinar. Nada foi alterado. A palavra-passe protege esta chave mesmo quando não é usada para iniciar sessão, por isso não pode ser removida enquanto a chave existir; repetir a operação não a resolve. Os detalhes técnicos indicam o que ficaria na conta.',

  // ═══ THE NOUN LIVES IN THE KEY ════════════════════════════════════════════════════════════
  // «A entidade» / «O livro» / «A ata» — the article alone already makes a single templated
  // sentence impossible. These are the keys that exist to prove the rule.
  'apiError.not_found.entity': 'A entidade indicada não existe.',
  'apiError.not_found.book': 'O livro indicado não existe.',
  'apiError.not_found.act': 'A ata indicada não existe.',
  'apiError.not_found.document': 'O documento indicado não existe.',
  'apiError.not_found.template': 'O modelo indicado não existe.',
  'apiError.not_found.user': 'O utilizador indicado não existe.',
  'apiError.not_found.signature_slot': 'O lugar de assinatura indicado não existe.',
  'apiError.not_found.retention_policy': 'A política de conservação indicada não existe.',
  'apiError.not_found.api_key': 'A chave API indicada não existe.',

  'apiError.already_exists.entity': 'Esta entidade já existe.',
  'apiError.already_exists.book': 'Este livro já existe.',
  'apiError.already_exists.act': 'Esta ata já existe.',
  'apiError.already_exists.user': 'Este utilizador já existe.',
  'apiError.already_exists.template': 'Este modelo já existe.',
  'apiError.already_exists.api_key': 'Esta chave API já existe.',
  'apiError.already_exists.record': 'Este registo já existe.',

  // ═══ LIVROS AND ATAS ══════════════════════════════════════════════════════════════════════
  'apiError.book_not_open': 'Este livro não está aberto, por isso não pode ser encerrado.',
  'apiError.book_capacity_exhausted':
    'O livro chegou ao número de páginas declarado no termo de abertura. Encerre-o e abra um livro novo.',
  'apiError.book_page_capacity_exceeded': 'A ata não cabe nas páginas que restam neste livro.',
  'apiError.act_not_signed_pdf': 'Esta ata ainda não tem PDF assinado.',
  'apiError.act_not_in_signing': 'Esta ata não está em assinatura, por isso não pode ser selada.',
  'apiError.act_wrong_book': 'Esta ata pertence a outro livro.',
  'apiError.act_has_no_convening': 'Esta ata não tem convocatória para enviar.',
  'apiError.chain_would_break':
    'Este registo não pode ser acrescentado: quebraria a cadeia de eventos já registada. Nada foi escrito.',
  'apiError.manual_signature_reference_required':
    'A selagem com assinatura manuscrita exige a referência ao original em papel.',
  'apiError.invalid_signature_evidence': 'A prova de assinatura apresentada não é válida.',
  'apiError.signing_session_expired':
    'Esta sessão de assinatura expirou ou já foi utilizada. Inicie uma assinatura nova.',

  // ═══ ASSINATURA ═══════════════════════════════════════════════════════════════════════════
  'apiError.signing_provider_refused': 'O prestador de assinatura recusou o pedido.',
  'apiError.cmd_refused': 'A Chave Móvel Digital recusou o pedido.',
  'apiError.cmd_config_invalid':
    'A configuração da Chave Móvel Digital está incorreta. Corrija-a nas definições antes de assinar.',
  // The CMD signing-flow error vocabulary (`chancela_cmd::CmdError::stable_code`). Each is the
  // headline for one class of runtime failure; the server's own English detail rides in the details
  // block. `apiErrorFallback.test.ts` reads the code list out of `crates/chancela-cmd/src/error.rs`
  // and proves none of these is left without copy.
  'apiError.cmd_transport_failed':
    'Não foi possível contactar a Chave Móvel Digital. Verifique a ligação à rede e tente novamente.',
  'apiError.cmd_response_too_large':
    'A Chave Móvel Digital devolveu uma resposta demasiado grande, que foi recusada por segurança. Tente novamente; se persistir, contacte quem administra o sistema.',
  'apiError.cmd_request_build_failed':
    'Não foi possível preparar o pedido à Chave Móvel Digital. Contacte quem administra o sistema.',
  'apiError.cmd_response_unreadable':
    'A resposta da Chave Móvel Digital não pôde ser interpretada. Tente novamente; se persistir, contacte quem administra o sistema.',
  'apiError.cmd_soap_fault':
    'A Chave Móvel Digital devolveu um erro de serviço. Tente novamente dentro de momentos.',
  'apiError.cmd_service_rejected':
    'A Chave Móvel Digital recusou iniciar a assinatura. Confirme o número de telemóvel e o PIN de assinatura e tente novamente.',
  'apiError.cmd_otp_rejected':
    'O código enviado por mensagem estava incorreto ou já expirou. Peça um novo código e tente novamente.',
  'apiError.cmd_configuration_invalid':
    'A configuração da Chave Móvel Digital não está completa ou é inválida. Corrija-a nas definições de assinatura antes de assinar.',
  'apiError.cmd_field_encryption_failed':
    'Não foi possível cifrar os dados enviados à Chave Móvel Digital com o certificado configurado. Verifique o certificado de cifra nas definições de assinatura.',
  'apiError.cmd_certificate_chain_invalid':
    'Não foi possível ler o certificado que a Chave Móvel Digital devolveu para o signatário. Tente novamente; se persistir, contacte quem administra o sistema.',
  'apiError.cmd_base64_invalid':
    'A Chave Móvel Digital devolveu um valor que não pôde ser descodificado. Tente novamente; se persistir, contacte quem administra o sistema.',
  'apiError.tsa_config_invalid':
    'A configuração do serviço de carimbo temporal está incorreta. Corrija-a nas definições.',
  'apiError.timestamp_failed': 'Não foi possível obter o carimbo temporal.',
  'apiError.qualified_timestamp_failed': 'Não foi possível obter o carimbo temporal qualificado.',
  'apiError.xades_production_failed': 'Não foi possível produzir a assinatura XAdES.',
  'apiError.xades_validation_failed': 'Não foi possível validar a assinatura XAdES.',
  'apiError.asic_production_failed': 'Não foi possível produzir o contentor ASiC.',
  'apiError.ltv_failed':
    'Não foi possível acrescentar os elementos de validação a longo prazo à assinatura.',
  'apiError.dss_vri_failed':
    'Não foi possível anexar os elementos de validação ao documento assinado.',
  'apiError.scap_config_invalid':
    'A configuração dos atributos profissionais (SCAP) está incorreta.',
  'apiError.scap_signature_failed': 'A assinatura com atributos profissionais (SCAP) falhou.',
  'apiError.scap_verification_failed': 'A verificação dos atributos profissionais (SCAP) falhou.',
  'apiError.pkcs12_password_incorrect': 'A palavra-passe do ficheiro PKCS#12 está incorreta.',
  'apiError.pkcs12_material_invalid':
    'O ficheiro PKCS#12 não contém material de assinatura utilizável.',
  'apiError.pkcs12_signing_failed': 'A assinatura com o ficheiro PKCS#12 local falhou.',
  'apiError.visible_seal_failed': 'Não foi possível preparar o selo visível do documento.',
  'apiError.seal_image_invalid': 'A imagem do selo não está em base64 válido.',
  'apiError.cc_card_absent':
    'Não foi detetado nenhum Cartão de Cidadão no leitor. Insira o cartão e tente de novo.',
  'apiError.cc_reader_absent':
    'Não foi detetado nenhum leitor de cartões. Ligue o leitor e tente de novo.',
  'apiError.cc_signature_not_activated':
    'A função de assinatura do Cartão de Cidadão não está ativada. Ative-a na aplicação Autenticação.gov.',
  'apiError.cc_local_signing_required':
    'A assinatura com Cartão de Cidadão só funciona na aplicação instalada neste computador, porque o cartão está no leitor local. Abra a aplicação de secretária para assinar.',
  'apiError.lotl_config_invalid': 'A configuração das âncoras de confiança está incorreta.',

  // ═══ CONTEÚDO ENVIADO ═════════════════════════════════════════════════════════════════════
  'apiError.invalid_request_body': 'O corpo do pedido não tem o formato esperado.',
  'apiError.invalid_settings_document': 'O documento de definições não tem o formato esperado.',
  'apiError.invalid_preferences_document':
    'O documento de preferências não tem o formato esperado.',
  'apiError.invalid_base64_content': 'O conteúdo enviado não está em base64 válido.',
  'apiError.invalid_base64_pdf': 'O PDF enviado não está em base64 válido.',
  'apiError.invalid_base64_document': 'O documento enviado não está em base64 válido.',
  'apiError.invalid_base64_certificate': 'O certificado enviado não está em base64 válido.',
  'apiError.invalid_base64_archive': 'O arquivo enviado não está em base64 válido.',
  'apiError.empty_content': 'O conteúdo enviado está vazio.',
  'apiError.empty_package': 'O pacote enviado está vazio.',
  'apiError.invalid_package': 'O pacote enviado não é válido.',
  'apiError.invalid_backup': 'A cópia de segurança não é válida.',
  'apiError.invalid_backup_request': 'O pedido de cópia de segurança não é válido.',
  'apiError.attachment_digest_invalid':
    'O resumo criptográfico do anexo não está em hexadecimal SHA-256 válido.',
  'apiError.evidence_digest_invalid':
    'O resumo criptográfico da prova não está em hexadecimal SHA-256 válido.',
  'apiError.pending_upload_malformed': 'O envio pendente está corrompido. Repita o envio.',
  'apiError.unknown_template_id': 'Não existe nenhum modelo com o identificador indicado.',
  'apiError.unknown_credential_mode': 'O modo de credencial indicado não é reconhecido.',

  // ═══ VALIDAÇÃO DE CAMPOS ══════════════════════════════════════════════════════════════════
  // The server's `{field} is required` family. The field NAME is deliberately not interpolated —
  // it is an English identifier and a noun, and both would break the sentence. It travels in the
  // details block and in `ApiError.field`, which the form uses to mark the input itself.
  'apiError.field_required':
    'Falta preencher um campo obrigatório. Os detalhes técnicos indicam qual.',
  'apiError.field_blank':
    'Um campo obrigatório ficou em branco. Os detalhes técnicos indicam qual.',
  'apiError.field_not_uuid': 'Um dos identificadores enviados não tem um formato válido.',
  'apiError.field_not_timestamp':
    'Uma das datas enviadas não está no formato de data e hora esperado.',
  'apiError.field_not_der_base64': 'Um dos certificados enviados não está em base64 DER válido.',
  'apiError.field_url_rejected':
    'Um dos endereços indicados foi recusado pela política de endereços de saída.',
  'apiError.invalid_date': 'A data indicada não é válida. Use o formato AAAA-MM-DD.',
  'apiError.invalid_time': 'A hora indicada não é válida. Use o formato HH:MM.',
  'apiError.invalid_search_date': 'A data de pesquisa indicada não é válida.',
  'apiError.invalid_search_cursor': 'O cursor de pesquisa deixou de ser válido. Refaça a pesquisa.',
  'apiError.fiscal_year_end_format': 'O fim do ano fiscal tem de ser indicado no formato MM-DD.',
  'apiError.name_empty': 'O nome não pode ficar vazio.',
  'apiError.date_range_overflow':
    'O intervalo de datas indicado ultrapassa a data máxima suportada.',
  'apiError.invalid_nipc': 'O NIPC indicado não é válido. Confirme os nove algarismos.',

  // ═══ CONFIGURAÇÃO E ARMAZENAMENTO ═════════════════════════════════════════════════════════
  'apiError.data_dir_required':
    'Esta operação exige que a aplicação esteja a guardar dados em disco. Esta instância está a funcionar apenas em memória.',
  'apiError.data_dir_missing': 'A pasta de dados configurada não existe.',
  'apiError.disk_persistence_required': 'Esta operação exige persistência em disco.',
  'apiError.connector_allowed_hosts_invalid':
    'A lista de anfitriões permitidos para ligações externas não é válida.',
  'apiError.provider_endpoint_invalid':
    'O endereço do prestador tem de ser um endereço HTTP(S) absoluto.',
  'apiError.layout_defaults_invalid':
    'As predefinições de composição do documento não são válidas.',
  'apiError.document_layout_invalid': 'A composição do documento indicada não é válida.',
  'apiError.template_preview_samples_invalid':
    'Os exemplos de pré-visualização do modelo não são válidos.',
  'apiError.required_signatories_invalid': 'A lista de signatários obrigatórios não é válida.',
  'apiError.shared_object_root_invalid': 'A raiz do repositório partilhado não é válida.',
  'apiError.repository_policy_requires_custody':
    'Uma política de repositório explícita exige que a custódia esteja definida.',
  'apiError.template_revision_exhausted':
    'O contador de revisões da biblioteca de modelos chegou ao limite.',
  'apiError.template_library_no_initial_revision':
    'A biblioteca de modelos não tem revisão inicial.',
  'apiError.api_key_changed_retry_rotation': 'A chave API mudou entretanto. Repita a rotação.',
  'apiError.role_not_reconcilable':
    'A função indicada não é uma função predefinida que possa ser reconciliada.',
  'apiError.index_rebuild_requires_resume': 'Retome o índice antes de pedir uma reconstrução.',
  'apiError.zk_path_escaped_root':
    'Um caminho do repositório de arquivo saiu da raiz configurada. A operação foi cancelada sem alterar nada.',
  'apiError.zk_object_missing_repository':
    'Uma versão de objeto aponta para um repositório que não existe.',
  'apiError.ciphertext_fixity_failed':
    'Os dados cifrados guardados não passaram a verificação de integridade. A operação foi cancelada.',
  'apiError.nonce_invariant_failed':
    'Falhou uma garantia interna de unicidade criptográfica. A operação foi cancelada sem escrever nada.',

  // ═══ PRIVACIDADE E CONSERVAÇÃO ════════════════════════════════════════════════════════════
  'apiError.retention_policy_required':
    'É preciso escolher uma política de conservação antes de executar a eliminação.',
  'apiError.legal_hold_reason_required':
    'A suspensão por motivo legal exige que o motivo seja indicado.',
  'apiError.reanchor_reason_required': 'A reancoragem exige um motivo, que não pode ficar vazio.',
  'apiError.invalid_target_scope': 'O âmbito indicado não é válido.',
  'apiError.erasure_plan_action_required':
    'O plano de eliminação tem de indicar a ação a executar.',

  // ═══ SERVIÇOS EXTERNOS ════════════════════════════════════════════════════════════════════
  'apiError.registry_code_invalid':
    'O código de acesso à certidão permanente não tem o número de algarismos esperado.',
  'apiError.registry_unreachable':
    'Não foi possível consultar o registo comercial. Volte a tentar dentro de momentos.',
  'apiError.registry_unrecognised':
    'A resposta do registo comercial não foi reconhecida como uma certidão permanente.',
  'apiError.cae_update_failed':
    'Não foi possível atualizar a tabela CAE a partir da origem oficial.',
  'apiError.cae_config_invalid': 'A origem da tabela CAE não está configurada.',

  // ═══ FALHAS INTERNAS — capped at one code each (never granular: see §4.2) ═════════════════
  'apiError.internal':
    'Ocorreu uma falha interna. O detalhe ficou registado no servidor; indique o identificador do pedido a quem administra o sistema.',
  'apiError.upstream':
    'Um serviço externo não respondeu como esperado. O detalhe ficou registado no servidor; indique o identificador do pedido a quem administra o sistema.',

  // ═══ CMD PRODUCTION TEST SIGNATURE (t112) ═════════════════════════════════════════════════
  // Every refusal here is fail-closed and by design: the flow costs one real qualified signature,
  // so it stops rather than improvising. The server's own pt-PT sentence still rides in the
  // details block; this is the headline above it, and the reason the other 13 locales stop
  // reading a Portuguese sentence in an otherwise translated dialog.
  'apiError.cmd_test_phone_invalid':
    'O número de telemóvel não tem o formato que a Chave Móvel Digital aceita.',
  'apiError.cmd_test_requires_production':
    'A assinatura de teste foi recusada: só corre contra o ambiente de produção da Chave Móvel Digital. Repetir não altera o resultado.',
  'apiError.cmd_test_environment_preprod':
    'A assinatura de teste foi recusada: esta instalação está configurada para pré-produção. Repetir não altera o resultado enquanto o ambiente não for mudado nas definições de assinatura.',
  'apiError.cmd_test_simulated_transport':
    'A assinatura de teste foi recusada: esta instância usa um transporte simulado, e um teste de produção não corre contra uma simulação. Repetir não altera o resultado.',
  'apiError.cmd_test_no_retention_storage':
    'A assinatura de teste foi recusada antes de assinar: esta instância não guarda ficheiros em disco, pelo que uma assinatura qualificada real não poderia ser conservada. Nada foi assinado, e repetir não altera o resultado.',
  'apiError.cmd_test_credentials_missing':
    'A assinatura de teste foi recusada: não há credencial da Chave Móvel Digital configurada. Repetir não altera o resultado enquanto os campos em falta não forem preenchidos.',
  'apiError.cmd_test_entry_unavailable':
    'A assinatura de teste foi recusada: a credencial indicada não existe ou está desativada, e o teste não recorre a outra. Repetir não altera o resultado.',
  'apiError.cmd_test_initiator_only':
    'A confirmação foi recusada: só quem iniciou a assinatura de teste a pode confirmar. Repetir não altera o resultado.',
  'apiError.cmd_test_session_expired':
    'O código da assinatura de teste expirou antes de ser confirmado e nada foi assinado. Inicie um teste novo para receber outro código.',

  // The saved CMD number (`/v1/me/cmd-phone`). Deliberate refusals, not hiccups: each says what
  // would have to change, because repeating the same request would land in the same place.
  'apiError.cmd_phone_no_unlocked_key':
    'Para guardar o número é preciso iniciar sessão com a palavra-passe: o número é cifrado com a sua chave de atestação, que tem de estar aberta na sessão. Repetir nesta sessão não altera o resultado.',
  'apiError.cmd_phone_invalid':
    'O número indicado não tem o formato de um número de telemóvel. Escreva-o em formato internacional, por exemplo +351 900 000 000.',
  'apiError.cmd_phone_unreadable':
    'O número guardado foi cifrado com uma chave de atestação que esta conta já não tem, pelo que não pode ser lido por ninguém. Guarde o número de novo para substituir o registo ilegível.',

  // ═══ THE TECHNICAL-DETAILS BLOCK (consumed by t58-e6's ErrorNote) ═════════════════════════
  'apiError.details.summary': 'Detalhes técnicos',
  'apiError.details.code': 'Código',
  'apiError.details.status': 'Estado HTTP',
  'apiError.details.requestId': 'Identificador do pedido',
  'apiError.details.path': 'Endereço do pedido',
  'apiError.details.detail': 'Detalhe do servidor',
  'apiError.details.copy': 'Copiar detalhes',
  'apiError.details.copied': 'Detalhes copiados',
  'apiError.details.hint':
    'Esta informação é técnica e está em inglês. Serve para quem administra o sistema diagnosticar o problema.',
} as const;

/** The key set the API-error copy resolves. */
export type ApiErrorCopyKey = keyof typeof apiErrorPtPT;

/** English fallback, served to the other 13 locales. */
export const apiErrorEnglish = {
  'apiError.tier.400': 'The request was not accepted as sent.',
  'apiError.tier.401': 'Your identity could not be confirmed for this operation.',
  'apiError.tier.403': 'You are not authorised to perform this operation.',
  'apiError.tier.404': 'What you asked for was not found.',
  'apiError.tier.409': 'The operation was refused because the current state does not allow it.',
  'apiError.tier.410': 'What you asked for is no longer available.',
  'apiError.tier.422': 'The request could not be processed as sent.',
  'apiError.tier.429': 'Too many requests were made. Wait before trying again.',
  'apiError.tier.500': 'An internal server failure occurred.',
  'apiError.tier.502': 'An external service did not respond as expected.',
  'apiError.tier.503': 'The service is unavailable right now. Try again shortly.',
  'apiError.tier.unknown': 'The operation did not complete.',

  'apiError.compliance_blocked':
    'Sealing was refused: compliance requirements are outstanding. Each unmet requirement is listed below with the legal basis it comes from. Resolve them and submit again.',
  'apiError.warnings_not_acknowledged':
    'Sealing will not proceed until you acknowledge the warnings listed below. Read each one and acknowledge it explicitly; dismissing this notice does not acknowledge them.',

  'apiError.invalid_act_body':
    'The minutes text was rejected and nothing was saved. The offending point is marked in the editor.',
  'apiError.unsupported_markdown':
    'The minutes text uses formatting the document cannot represent. Nothing was converted or removed — fix the marked point and save again.',
  'apiError.invalid_placeholder':
    'The minutes text contains a malformed merge field. Fix the marked point and save again.',
  'apiError.body_too_large':
    'The minutes text exceeds the maximum accepted size. Shorten it and save again.',
  'apiError.body_block_too_large':
    'One paragraph of the minutes exceeds the maximum accepted size. Split it and save again.',

  'apiError.termo_stale_facts':
    'The book changed after this termo de encerramento was frozen for signature: the figures declared in the signed termo no longer match the book. Sealing it would make the signed document contradict the record, so it was refused. Prepare the termo de encerramento again with the current figures.',
  'apiError.termo_snapshot_render_drift':
    'The termo de encerramento document no longer matches what was signed, even though the declared figures are still correct. What changed is how the document is laid out, not the book’s figures. Sealing a document other than the one that was signed is not permitted, so the request was refused. Prepare the termo de encerramento again.',
  'apiError.termo_snapshot_mismatch':
    'The termo de encerramento document no longer matches what was signed. Where it diverged could not be established, and a signed termo that does not match the book cannot be sealed. Prepare the termo de encerramento again.',
  'apiError.termo_encerramento_not_signed':
    'The book was not closed: at least one required signatory of the termo de encerramento has no cryptographic signature. This is a refusal, not a transient failure — retrying will not resolve it.',

  'apiError.termo_seed_template_drift':
    'This termo still carries clauses seeded from an earlier version of the template, but it would be frozen against the current version, which no longer includes that text. Review the termo clauses and save them before freezing it for signature.',

  'apiError.termo_abertura_not_signed':
    'The book was not opened: the termo de abertura is not yet cryptographically signed by every required signatory. This is a deliberate refusal, not a transient failure — retrying will not resolve it. Every required signatory must sign the termo cryptographically before the book can open.',

  'apiError.cc_pin_blocked':
    'The Cartão de Cidadão PIN is blocked after too many incorrect attempts. The card will not sign again while it is blocked: unblock it with the PUK in the Autenticação.gov application.',
  'apiError.cc_pin_wrong': 'The Cartão de Cidadão PIN is incorrect. Check it and try again.',
  'apiError.cc_pin_wrong.low':
    'The Cartão de Cidadão PIN is incorrect. Few attempts remain before the card blocks.',
  'apiError.cc_pin_wrong.final_try':
    'The Cartão de Cidadão PIN is incorrect and one attempt remains. If it fails again the card blocks and only the PUK will unblock it.',
  'apiError.cc_pin_wrong.locked':
    'The Cartão de Cidadão PIN was incorrect and the card is now blocked. Unblock it with the PUK in the Autenticação.gov application.',

  'apiError.signin_throttled':
    'Too many sign-in attempts on this account. Wait {seconds} s before trying again. This limit protects the account against repeated attempts.',
  'apiError.signin_throttled.no_wait':
    'Too many sign-in attempts on this account. Wait and try again later. This limit protects the account against repeated attempts.',
  'apiError.credential_proof_throttled':
    'Too many attempts with the current password. Wait {seconds} s before trying again.',
  'apiError.api_key_rate_limited':
    'The API key exceeded its request limit. Wait {seconds} s before repeating the request.',

  'apiError.cluster_not_leader':
    'This node is not accepting writes right now: the server set is electing the node responsible for writes. The operation was not performed. Try again within seconds — once the election settles, the request goes through.',
  'apiError.shared_sessions_unavailable':
    'The shared session service could not be reached, so the operation was cancelled without changing anything. Try again shortly.',

  'apiError.cross_user_proof_required':
    'Changing another user’s credentials requires that user’s current password or a valid recovery phrase. The request was refused. For security, the answer is the same whether the proof is wrong, missing, or the named account does not exist — it neither confirms nor denies that any account exists.',
  'apiError.cross_user_recovery_cannot_generate_key':
    'An attestation key cannot be generated from the recovery phrase alone: the key is protected by the user’s current password, which must be supplied.',

  'apiError.trust_anchor_not_configured':
    'Qualified signing was refused because this server has no trust anchors configured yet. Without them no certificate can be treated as trusted. Configure the Trusted List in settings before signing again.',
  'apiError.trusted_list_not_anchored':
    'Qualified signing was refused because the Trusted List did not authenticate against the configured trust anchor. The anchor may not match this list, or a key rotation may have replaced it with a signing certificate that is not configured yet. Check the anchor in settings: the problem is on this side, not the signer’s provider.',
  'apiError.signer_service_not_active':
    'Qualified signing was refused because the signer’s trust service is not listed as active in the Trusted List. The problem is on the provider’s side, not this server’s.',

  'apiError.signing_trusted_list_unavailable':
    'Signing did not proceed because the Trusted List could not be fetched or read. Without it there is no verdict at all on the signer’s certificate: what failed was reaching the list, not the certificate. Check the Trusted List address in the signing settings and this server’s outbound connectivity.',
  'apiError.signing_trusted_list_tls_chain_incomplete':
    'Signing did not proceed because the server hosting the Trusted List did not send its full certificate chain: the intermediate certificate linking that server’s certificate to a trusted root is missing. The fault is at that server, not at this installation — the address is correct and the connection reached it. A browser or curl may open the same address without error, because they fetch missing certificates automatically and this client does not. Supply the missing intermediate certificate in the signing settings, under signing.tls_intermediate_certs.',
  'apiError.signing_timestamp_failed':
    'The timestamp authority did not return a usable timestamp, so the signature was not completed. Check the timestamping service address in the signing settings and try again.',
  'apiError.signing_not_implemented':
    'The signing operation requested is not implemented in this version. This is not a transient failure — repeating it changes nothing. Choose a format or profile this installation produces; the technical details name what was requested.',
  'apiError.signing_unsupported_format':
    'This installation does not produce the signature format requested. Repeating it changes nothing: choose one of the supported formats. The technical details name what was asked for.',
  'apiError.signing_unsupported_profile':
    'The signature profile requested is recognised but is not supported by this installation. Repeating it changes nothing. The technical details name the profile and the alternatives available.',
  'apiError.signing_format_input_mismatch':
    'The document sent does not match the signature format requested — a PAdES signature, for example, needs the bytes of a PDF. The technical details name the expected format.',
  'apiError.signing_family_mismatch':
    'The chosen provider does not belong to the signing family this signature slot requires. Choose a provider from the required family; the technical details name both.',
  'apiError.signing_issuer_certificate_missing':
    'The certificate of the authority that issued the signer’s certificate could not be obtained, so the Trusted List check could not be performed. A qualified signature does not skip that check, so the request was refused.',
  'apiError.signing_cades_failed':
    'The signature’s CAdES/CMS cryptographic structure could not be assembled or validated. The fault is on this server, not an external service; the technical details name the component involved.',
  'apiError.signing_pades_failed':
    'The PDF could not be signed or validated in the PAdES structure. The fault is on this server, not an external service; the technical details name the component involved.',
  'apiError.signing_asic_failed':
    'The ASiC container could not be created, read or validated. The fault is on this server, not an external service; the technical details name the component involved.',
  'apiError.signing_xades_failed':
    'The XAdES/XMLDSig signature could not be assembled or validated. The fault is on this server, not an external service; the technical details name the component involved.',
  'apiError.signing_slot_out_of_range':
    'The signature slot given does not exist in this signature set. Reload the page and choose one of the available slots.',
  'apiError.signing_slot_already_signed':
    'This signature slot has already been signed, so it cannot be signed again. Nothing was changed.',
  'apiError.signing_slot_out_of_order':
    'This signature set is sequential and an earlier slot is still unsigned. Sign the outstanding slot first; the technical details name which one.',
  'apiError.signing_wrong_path':
    'This signature slot cannot be signed through this route: a scanned handwritten signature and a qualified signature follow different paths. Use the route matching this slot’s family.',

  'apiError.session_required':
    'This operation requires a signed-in session. Sign in and try again.',
  'apiError.session_invalid': 'The session has ended or is no longer valid. Sign in again.',
  'apiError.session_without_active_user': 'The session is not tied to any active user.',
  'apiError.invalid_credentials': 'The credentials supplied are incorrect.',
  'apiError.current_password_incorrect': 'The current password is incorrect.',
  'apiError.two_factor_challenge_invalid':
    'The second-factor code is incorrect or has expired. Request a new one and try again.',
  'apiError.pairing_code_invalid':
    'The pairing code is incorrect or has expired. Generate a new code.',
  'apiError.session_or_api_key_not_both':
    'Send either a session or an API key, never both on the same request.',
  'apiError.api_key_no_interactive_session':
    'An API key does not open an interactive session. Use a user’s credentials for this operation.',
  'apiError.invite_invalid_or_expired':
    'The invitation is invalid or has expired. Request a new one.',
  'apiError.delegation_refused':
    'The delegation was refused in full. None of the requested permissions were granted.',
  'apiError.password_policy':
    'The password does not meet the security requirements. The unmet requirements are listed below.',

  'apiError.account_would_have_no_sign_in_credential':
    'The operation was refused: it would leave this account with no credential to sign in with, and nobody could get back into it. Nothing was changed. Establish another way to sign in before removing this one; repeating the operation will not resolve it. The technical details name what the account would be left holding.',
  'apiError.account_would_have_no_recovery_credential':
    'The operation was refused: it would remove a way to sign in while leaving the account with no way to be recovered, and losing the remaining credential would leave the account unreachable. Nothing was changed. Issue a recovery phrase before removing this credential; repeating the operation will not resolve it. The technical details name what the account would be left holding.',
  'apiError.account_attestation_key_would_have_no_wrap':
    'The operation was refused: this account’s signing key would be left with no protection that can be opened, and the account could never sign again. Nothing was changed. The password protects this key even when it is not used to sign in, so it cannot be removed while the key exists; repeating the operation will not resolve it. The technical details name what the account would be left holding.',

  'apiError.not_found.entity': 'The entity you asked for does not exist.',
  'apiError.not_found.book': 'The book you asked for does not exist.',
  'apiError.not_found.act': 'The minutes you asked for do not exist.',
  'apiError.not_found.document': 'The document you asked for does not exist.',
  'apiError.not_found.template': 'The template you asked for does not exist.',
  'apiError.not_found.user': 'The user you asked for does not exist.',
  'apiError.not_found.signature_slot': 'The signature slot you asked for does not exist.',
  'apiError.not_found.retention_policy': 'The retention policy you asked for does not exist.',
  'apiError.not_found.api_key': 'The API key you asked for does not exist.',

  'apiError.already_exists.entity': 'This entity already exists.',
  'apiError.already_exists.book': 'This book already exists.',
  'apiError.already_exists.act': 'These minutes already exist.',
  'apiError.already_exists.user': 'This user already exists.',
  'apiError.already_exists.template': 'This template already exists.',
  'apiError.already_exists.api_key': 'This API key already exists.',
  'apiError.already_exists.record': 'This record already exists.',

  'apiError.book_not_open': 'This book is not open, so it cannot be closed.',
  'apiError.book_capacity_exhausted':
    'The book has reached the page count declared in its termo de abertura. Close it and open a new book.',
  'apiError.book_page_capacity_exceeded':
    'The minutes do not fit in the pages remaining in this book.',
  'apiError.act_not_signed_pdf': 'These minutes do not have a signed PDF yet.',
  'apiError.act_not_in_signing': 'These minutes are not in signing, so they cannot be sealed.',
  'apiError.act_wrong_book': 'These minutes belong to a different book.',
  'apiError.act_has_no_convening': 'These minutes have no convening notice to dispatch.',
  'apiError.chain_would_break':
    'This entry cannot be appended: it would break the event chain already recorded. Nothing was written.',
  'apiError.manual_signature_reference_required':
    'Sealing with a handwritten signature requires the reference to the paper original.',
  'apiError.invalid_signature_evidence': 'The signature evidence supplied is not valid.',
  'apiError.signing_session_expired':
    'This signing session has expired or has already been used. Start a new signature.',

  'apiError.signing_provider_refused': 'The signing provider refused the request.',
  'apiError.cmd_refused': 'Chave Móvel Digital refused the request.',
  'apiError.cmd_config_invalid':
    'The Chave Móvel Digital configuration is incorrect. Fix it in settings before signing.',
  'apiError.cmd_transport_failed':
    'Chave Móvel Digital could not be reached. Check the network connection and try again.',
  'apiError.cmd_response_too_large':
    'Chave Móvel Digital returned an oversized response, which was refused as a safety measure. Try again; if it persists, contact whoever administers the system.',
  'apiError.cmd_request_build_failed':
    'The request to Chave Móvel Digital could not be prepared. Contact whoever administers the system.',
  'apiError.cmd_response_unreadable':
    'The response from Chave Móvel Digital could not be read. Try again; if it persists, contact whoever administers the system.',
  'apiError.cmd_soap_fault': 'Chave Móvel Digital returned a service fault. Try again in a moment.',
  'apiError.cmd_service_rejected':
    'Chave Móvel Digital refused to start the signature. Check the mobile number and signing PIN and try again.',
  'apiError.cmd_otp_rejected':
    'The code sent by SMS was incorrect or has expired. Request a new code and try again.',
  'apiError.cmd_configuration_invalid':
    'The Chave Móvel Digital configuration is incomplete or invalid. Fix it in the signing settings before signing.',
  'apiError.cmd_field_encryption_failed':
    'The data sent to Chave Móvel Digital could not be encrypted with the configured certificate. Check the field-encryption certificate in the signing settings.',
  'apiError.cmd_certificate_chain_invalid':
    'The certificate Chave Móvel Digital returned for the signer could not be read. Try again; if it persists, contact whoever administers the system.',
  'apiError.cmd_base64_invalid':
    'Chave Móvel Digital returned a value that could not be decoded. Try again; if it persists, contact whoever administers the system.',
  'apiError.tsa_config_invalid':
    'The timestamping service configuration is incorrect. Fix it in settings.',
  'apiError.timestamp_failed': 'The timestamp could not be obtained.',
  'apiError.qualified_timestamp_failed': 'The qualified timestamp could not be obtained.',
  'apiError.xades_production_failed': 'The XAdES signature could not be produced.',
  'apiError.xades_validation_failed': 'The XAdES signature could not be validated.',
  'apiError.asic_production_failed': 'The ASiC container could not be produced.',
  'apiError.ltv_failed': 'The long-term validation material could not be added to the signature.',
  'apiError.dss_vri_failed':
    'The validation material could not be attached to the signed document.',
  'apiError.scap_config_invalid': 'The professional-attribute (SCAP) configuration is incorrect.',
  'apiError.scap_signature_failed': 'Signing with professional attributes (SCAP) failed.',
  'apiError.scap_verification_failed': 'Verifying the professional attributes (SCAP) failed.',
  'apiError.pkcs12_password_incorrect': 'The PKCS#12 file password is incorrect.',
  'apiError.pkcs12_material_invalid': 'The PKCS#12 file contains no usable signing material.',
  'apiError.pkcs12_signing_failed': 'Signing with the local PKCS#12 file failed.',
  'apiError.visible_seal_failed': 'The document’s visible seal could not be prepared.',
  'apiError.seal_image_invalid': 'The seal image is not valid base64.',
  'apiError.cc_card_absent':
    'No Cartão de Cidadão was detected in the reader. Insert the card and try again.',
  'apiError.cc_reader_absent': 'No card reader was detected. Connect the reader and try again.',
  'apiError.cc_signature_not_activated':
    'The Cartão de Cidadão signing function is not activated. Activate it in the Autenticação.gov application.',
  'apiError.cc_local_signing_required':
    'Cartão de Cidadão signing only works in the application installed on this computer, because the card is in the local reader. Open the desktop application to sign.',
  'apiError.lotl_config_invalid': 'The trust-anchor configuration is incorrect.',

  'apiError.invalid_request_body': 'The request body is not in the expected format.',
  'apiError.invalid_settings_document': 'The settings document is not in the expected format.',
  'apiError.invalid_preferences_document':
    'The preferences document is not in the expected format.',
  'apiError.invalid_base64_content': 'The content sent is not valid base64.',
  'apiError.invalid_base64_pdf': 'The PDF sent is not valid base64.',
  'apiError.invalid_base64_document': 'The document sent is not valid base64.',
  'apiError.invalid_base64_certificate': 'The certificate sent is not valid base64.',
  'apiError.invalid_base64_archive': 'The archive sent is not valid base64.',
  'apiError.empty_content': 'The content sent is empty.',
  'apiError.empty_package': 'The package sent is empty.',
  'apiError.invalid_package': 'The package sent is not valid.',
  'apiError.invalid_backup': 'The backup is not valid.',
  'apiError.invalid_backup_request': 'The backup request is not valid.',
  'apiError.attachment_digest_invalid': 'The attachment digest is not valid SHA-256 hexadecimal.',
  'apiError.evidence_digest_invalid': 'The evidence digest is not valid SHA-256 hexadecimal.',
  'apiError.pending_upload_malformed': 'The pending upload is malformed. Repeat the upload.',
  'apiError.unknown_template_id': 'No template exists with the identifier given.',
  'apiError.unknown_credential_mode': 'The credential mode given is not recognised.',

  'apiError.field_required': 'A required field is missing. The technical details name which one.',
  'apiError.field_blank': 'A required field was left blank. The technical details name which one.',
  'apiError.field_not_uuid': 'One of the identifiers sent is not in a valid format.',
  'apiError.field_not_timestamp':
    'One of the dates sent is not in the expected date-and-time format.',
  'apiError.field_not_der_base64': 'One of the certificates sent is not valid base64 DER.',
  'apiError.field_url_rejected':
    'One of the addresses given was rejected by the outbound address policy.',
  'apiError.invalid_date': 'The date given is not valid. Use the YYYY-MM-DD format.',
  'apiError.invalid_time': 'The time given is not valid. Use the HH:MM format.',
  'apiError.invalid_search_date': 'The search date given is not valid.',
  'apiError.invalid_search_cursor': 'The search cursor is no longer valid. Run the search again.',
  'apiError.fiscal_year_end_format': 'The fiscal year end must be given in MM-DD format.',
  'apiError.name_empty': 'The name cannot be left empty.',
  'apiError.date_range_overflow': 'The date range given goes past the maximum supported date.',
  'apiError.invalid_nipc': 'The NIPC given is not valid. Check the nine digits.',

  'apiError.data_dir_required':
    'This operation requires the application to be storing data on disk. This instance is running in memory only.',
  'apiError.data_dir_missing': 'The configured data directory does not exist.',
  'apiError.disk_persistence_required': 'This operation requires on-disk persistence.',
  'apiError.connector_allowed_hosts_invalid':
    'The list of hosts allowed for outbound connections is not valid.',
  'apiError.provider_endpoint_invalid':
    'The provider endpoint must be an absolute HTTP(S) address.',
  'apiError.layout_defaults_invalid': 'The document layout defaults are not valid.',
  'apiError.document_layout_invalid': 'The document layout given is not valid.',
  'apiError.template_preview_samples_invalid': 'The template preview samples are not valid.',
  'apiError.required_signatories_invalid': 'The list of required signatories is not valid.',
  'apiError.shared_object_root_invalid': 'The shared object root is not valid.',
  'apiError.repository_policy_requires_custody':
    'An explicit repository policy requires custody to be set.',
  'apiError.template_revision_exhausted':
    'The template library revision counter has reached its limit.',
  'apiError.template_library_no_initial_revision': 'The template library has no initial revision.',
  'apiError.api_key_changed_retry_rotation':
    'The API key changed in the meantime. Repeat the rotation.',
  'apiError.role_not_reconcilable': 'The role given is not a seeded role that can be reconciled.',
  'apiError.index_rebuild_requires_resume': 'Resume the index before requesting a rebuild.',
  'apiError.zk_path_escaped_root':
    'An archive repository path escaped its configured root. The operation was cancelled without changing anything.',
  'apiError.zk_object_missing_repository':
    'An object version references a repository that does not exist.',
  'apiError.ciphertext_fixity_failed':
    'The stored ciphertext failed its integrity check. The operation was cancelled.',
  'apiError.nonce_invariant_failed':
    'An internal cryptographic uniqueness guarantee failed. The operation was cancelled without writing anything.',

  'apiError.retention_policy_required':
    'A retention policy must be chosen before the disposal can run.',
  'apiError.legal_hold_reason_required': 'A legal hold requires the reason to be given.',
  'apiError.reanchor_reason_required': 'Re-anchoring requires a reason, which cannot be empty.',
  'apiError.invalid_target_scope': 'The target scope given is not valid.',
  'apiError.erasure_plan_action_required': 'The erasure plan must name the action to perform.',

  'apiError.registry_code_invalid':
    'The certidão permanente access code does not have the expected number of digits.',
  'apiError.registry_unreachable':
    'The commercial registry could not be consulted. Try again shortly.',
  'apiError.registry_unrecognised':
    'The commercial registry’s response was not recognised as a certidão permanente.',
  'apiError.cae_update_failed': 'The CAE table could not be updated from the official source.',
  'apiError.cae_config_invalid': 'The CAE table source is not configured.',

  'apiError.internal':
    'An internal failure occurred. The detail was recorded on the server; give the request identifier to whoever administers the system.',
  'apiError.upstream':
    'An external service did not respond as expected. The detail was recorded on the server; give the request identifier to whoever administers the system.',

  // ═══ CMD PRODUCTION TEST SIGNATURE (t112) ═════════════════════════════════════════════════
  'apiError.cmd_test_phone_invalid':
    'The phone number is not in the shape Chave Móvel Digital accepts.',
  'apiError.cmd_test_requires_production':
    'The test signature was refused: it only runs against the Chave Móvel Digital production environment. Repeating it changes nothing.',
  'apiError.cmd_test_environment_preprod':
    'The test signature was refused: this deployment is configured for preprod. Repeating it changes nothing until the environment is switched in the signing settings.',
  'apiError.cmd_test_simulated_transport':
    'The test signature was refused: this instance uses a simulated transport, and a production test does not run against a simulation. Repeating it changes nothing.',
  'apiError.cmd_test_no_retention_storage':
    'The test signature was refused before signing: this instance keeps no files on disk, so a real qualified signature could not be retained. Nothing was signed, and repeating it changes nothing.',
  'apiError.cmd_test_credentials_missing':
    'The test signature was refused: no Chave Móvel Digital credential is configured. Repeating it changes nothing until the missing fields are filled in.',
  'apiError.cmd_test_entry_unavailable':
    'The test signature was refused: the chosen credential does not exist or is disabled, and the test does not fall back to another. Repeating it changes nothing.',
  'apiError.cmd_test_initiator_only':
    'The confirmation was refused: only whoever started the test signature may confirm it. Repeating it changes nothing.',
  'apiError.cmd_test_session_expired':
    'The test-signature code expired before it was confirmed, and nothing was signed. Start a new test to receive another code.',

  'apiError.cmd_phone_no_unlocked_key':
    'Saving the number requires signing in with your password: the number is encrypted with your attestation key, which has to be unlocked in the session. Repeating this in the current session changes nothing.',
  'apiError.cmd_phone_invalid':
    'The number given is not shaped like a mobile number. Write it in international form, for example +351 900 000 000.',
  'apiError.cmd_phone_unreadable':
    'The saved number was encrypted with an attestation key this account no longer has, so nobody can read it. Save the number again to replace the unreadable record.',

  'apiError.details.summary': 'Technical details',
  'apiError.details.code': 'Code',
  'apiError.details.status': 'HTTP status',
  'apiError.details.requestId': 'Request identifier',
  'apiError.details.path': 'Request path',
  'apiError.details.detail': 'Server detail',
  'apiError.details.copy': 'Copy details',
  'apiError.details.copied': 'Details copied',
  'apiError.details.hint':
    'This information is technical and in English. It is here so whoever administers the system can diagnose the problem.',
} as const satisfies Record<ApiErrorCopyKey, string>;

/**
 * The only placeholder names this catalog may use. **Integers only** — every one of these is
 * agreement-inert, so no article, adjective or participle around it can disagree. Seconds render
 * against the symbol `s`, never a spelled-out noun, so `1` needs no singular form.
 *
 * A common noun, an entity kind, a field name or a type name must NEVER appear here: that is the
 * defect this catalog is shaped to make unmergeable. If a citation of a proper name is ever needed,
 * it goes inside «guillemets» — quoted text is cited, not grammatically incorporated — and is added
 * here deliberately, with review.
 */
export const ALLOWED_PLACEHOLDERS = ['seconds', 'count', 'max', 'offset', 'status'] as const;

/**
 * Placeholder names that are categorically forbidden — each resolves to a noun at runtime and each
 * breaks pt-PT agreement. Named explicitly so the gate's failure message can say *why*.
 */
export const FORBIDDEN_PLACEHOLDERS = [
  'entity',
  'resource',
  'kind',
  'field',
  'noun',
  'thing',
  'target',
  'type',
  'label',
  'scope',
  'name',
  'item',
  'object',
  'subject',
] as const;

/**
 * Codes whose copy is a **deliberate refusal or a hard limit**, not a transient failure. The
 * surfaces the plan pins as must-not-soften. A consumer must not render these as a dismissable
 * notice, must not offer a bare "try again", and must not collapse them into a generic tier
 * headline. `apiErrorFallback.test.ts` asserts every one has its own catalog key.
 */
export const NON_ROUTINE_CODES = [
  'compliance_blocked',
  'warnings_not_acknowledged',
  // `InvalidActBody` never puts `invalid_act_body` on the wire — it ships the *diagnostic* code from
  // `BodyRenderError::code()`. These four are the complete set it can emit, so they are what has to
  // be marked; listing the variant name instead protected the surface in name only.
  'invalid_placeholder',
  'unsupported_markdown',
  'body_too_large',
  'body_block_too_large',
  'termo_stale_facts',
  'termo_snapshot_render_drift',
  'termo_snapshot_mismatch',
  'termo_encerramento_not_signed',
  'termo_abertura_not_signed',
  'cc_pin_blocked',
  'signin_throttled',
  // The server emits the wait-less variant, not `signin_throttled`: the remaining seconds live only
  // inside the English `error` string and no structured field carries them, so the seconds-bearing
  // copy would render `{seconds}` verbatim. Listing only `signin_throttled` marked a code nothing
  // sends and left the one that IS sent unprotected — the same "guard that covers nothing" shape as
  // `invalid_act_body` above.
  'signin_throttled.no_wait',
  'credential_proof_throttled',
  'api_key_rate_limited',
  'cluster_not_leader',
  'cross_user_proof_required',
  // The account-lifecycle wall. Both are refusals of the *operation*, not failures of it: nothing
  // was changed, and the removal will be refused identically until another credential exists.
  'account_would_have_no_sign_in_credential',
  'account_would_have_no_recovery_credential',
  'account_attestation_key_would_have_no_wrap',
  // A refused qualified signature is a refusal, not a hiccup, and repeating it changes nothing
  // until the operator edits their anchor configuration.
  'trust_anchor_not_configured',
  'trusted_list_not_anchored',
  // Capability gaps: this build does not produce what was asked for, and no retry changes that.
  // Rendering them as an ordinary "something went wrong, try again" is the specific misdirection
  // that follows from a `_ =>` arm — which is exactly where they used to end up.
  'signing_not_implemented',
  'signing_unsupported_format',
  'signing_unsupported_profile',
  // Already signed: the refusal protects a signature that exists. Retrying re-refuses.
  'signing_slot_already_signed',
  // t112: the CMD production test-signature refusals. Each one stops BEFORE a real qualified
  // signature is produced and none of them clears on a retry — `cmd_test_session_expired` is
  // deliberately absent, because that one IS cleared by starting again.
  'cmd_test_requires_production',
  'cmd_test_environment_preprod',
  'cmd_test_simulated_transport',
  'cmd_test_no_retention_storage',
  'cmd_test_credentials_missing',
  'cmd_test_entry_unavailable',
  'cmd_test_initiator_only',
] as const;

/** Statuses with a guaranteed tier headline. Every status `ApiError` can produce is here. */
export const TIER_STATUSES = [400, 401, 403, 404, 409, 410, 422, 429, 500, 502, 503] as const;

/**
 * The Tier-1 variant-default codes (`ApiError::code()` with no per-site override). They carry no
 * information beyond the HTTP status, so they resolve to the status tier rather than duplicating it
 * as near-identical copy. They are NOT unmapped: this catalog has no gap, because there is no code
 * here to write copy for.
 *
 * **The CODE says nothing more; the DETAIL usually does.** This once concluded that "nothing more
 * specific is being hidden" and left the technical-details block collapsed. That is false about the
 * wire: `ApiError::Unprocessable("declared PDF SHA-256 digest does not match the received bytes")`
 * emits `http.unprocessable` and a fully specific English message, and `with_code` is opt-in per
 * site — the server has ~1100 such constructor sites against ~47 refined ones. Resolving to a tier
 * headline is therefore the COMMON case, not the residual one, and leaving the detail collapsed hid
 * the reason behind «O pedido não foi aceite tal como foi enviado.» for all of them. So a tier
 * headline force-opens the block (see {@link ApiErrorResolution.forceDetails}).
 */
const TIER_DEFAULT_CODES = new Set([
  'http.not_found',
  'http.conflict',
  'http.unprocessable',
  'http.unavailable',
  'http.gone',
  'http.too_many_requests',
  'http.unauthorized',
  'http.forbidden',
  'http.bad_request',
]);

/**
 * The two Tier-1 defaults that DO have dedicated copy. `Internal` and `Upstream` are the only
 * variants the server refuses to let a call site refine (`with_code` is a no-op for them), so their
 * code is intrinsic rather than "nothing specific assigned yet" — and their message is scrubbed off
 * the wire, which is exactly why they need their own sentence and a forced-open details block.
 *
 * The server sends the `http.`-prefixed form; the rest of this module speaks the bare name.
 */
const TIER_DEFAULT_ALIASES: Record<string, string> = {
  'http.internal': 'internal',
  'http.upstream': 'upstream',
};

/** The shape this module reads off a client `ApiError`. Structural, so tests need no class. */
export interface ApiErrorLike {
  status?: number;
  code?: string;
  pinStatus?: string;
  triesLeft?: string;
}

/** How an error resolved, and what the surface rendering it must do. */
export interface ApiErrorResolution {
  /** The catalog key for the headline. Always resolves — the tier keys are total over statuses. */
  key: ApiErrorCopyKey;
  /**
   * The server sent a `code` this catalog has no entry for, so the headline fell back to the status
   * tier. The English detail is NOT dropped — the surface must force the technical-details block
   * open so the operator still sees everything the server said.
   */
  unmapped: boolean;
  /**
   * The technical-details block must start expanded, because nothing on screen names the fault.
   *
   * True whenever the headline is a bare `apiError.tier.*` sentence — it names the HTTP status and
   * nothing else, so the server's English detail is the only thing that says what actually went
   * wrong — and for the scrubbed `internal`/`upstream`, whose copy is generic on purpose and whose
   * request id is the operator's only route back to the real fault.
   */
  forceDetails: boolean;
  /** A deliberate refusal: must not render as routine, dismissable, or a bare "try again". */
  nonRoutine: boolean;
}

const NON_ROUTINE = new Set<string>(NON_ROUTINE_CODES);

function hasKey(key: string): key is ApiErrorCopyKey {
  return Object.prototype.hasOwnProperty.call(apiErrorPtPT, key);
}

/**
 * Resolve a server error to its copy key.
 *
 * Order: a structured PIN status first (it is finer than the code and PIN-free), then the code, then
 * the status tier. There is no branch that returns the server's raw English as the headline, and no
 * branch that discards it — every branch that lands on a tier headline (an unmapped code, a Tier-1
 * variant default, or no code at all) demotes the English detail into the FORCED-OPEN details block
 * rather than dropping it or folding it shut (memory: `reject-never-silently-transform`).
 */
export function resolveApiError(error: ApiErrorLike | null | undefined): ApiErrorResolution {
  const status = error?.status;
  const rawCode = error?.code;
  // `http.internal`/`http.upstream` carry dedicated copy under their bare names; every other
  // `http.` code is a generic tier default and is matched as-is below.
  const code = rawCode === undefined ? undefined : (TIER_DEFAULT_ALIASES[rawCode] ?? rawCode);

  // A blocked card is terminal and a wrong PIN has a remaining-attempt hint; both are finer than
  // the `pin_rejected` code and neither may read as an ordinary retry.
  const pinStatus = error?.pinStatus;
  if (pinStatus === 'blocked') {
    return refusal('apiError.cc_pin_blocked');
  }
  if (pinStatus === 'wrong_pin') {
    const hinted = `apiError.cc_pin_wrong.${error?.triesLeft ?? ''}`;
    const key: ApiErrorCopyKey = hasKey(hinted) ? hinted : 'apiError.cc_pin_wrong';
    return { key, unmapped: false, forceDetails: false, nonRoutine: false };
  }

  if (code !== undefined && code !== '' && !TIER_DEFAULT_CODES.has(code)) {
    const key = `apiError.${code}`;
    if (hasKey(key)) {
      const nonRoutine = NON_ROUTINE.has(code);
      return {
        key,
        unmapped: false,
        // `internal`/`upstream` are scrubbed server-side: the client copy is generic on purpose, so
        // the request id is the operator's only route back to the real fault. Show it up front.
        forceDetails: code === 'internal' || code === 'upstream',
        nonRoutine,
      };
    }
    // An unmapped code is a gap in THIS catalog, not in the server. Make it loud to developers and
    // force the detail open for the operator, rather than quietly degrading to a generic sentence.
    if (import.meta.env.DEV) {
      console.warn(
        `[apiErrorFallback] no pt-PT copy for API error code "${code}" (status ${String(status)}); ` +
          'headline fell back to the status tier and the server detail was force-expanded.',
      );
    }
    return { key: tierKey(status), unmapped: true, forceDetails: true, nonRoutine: false };
  }

  // A Tier-1 variant default, or no code at all: the headline is the bare status tier, which names
  // the status and NOTHING about the fault. Whatever the server said is the only thing that does, so
  // it goes up front rather than behind a closed disclosure (see `TIER_DEFAULT_CODES`).
  return { key: tierKey(status), unmapped: false, forceDetails: true, nonRoutine: false };
}

function refusal(key: ApiErrorCopyKey): ApiErrorResolution {
  return { key, unmapped: false, forceDetails: false, nonRoutine: true };
}

/** The always-present headline for an HTTP status. Total: an unknown status still gets a sentence. */
export function tierKey(status: number | undefined): ApiErrorCopyKey {
  const key = `apiError.tier.${String(status)}`;
  return hasKey(key) ? key : 'apiError.tier.unknown';
}

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useApiErrorCopy(): Record<ApiErrorCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? apiErrorPtPT : apiErrorEnglish;
}

/**
 * The API-error translate hook, shaped like `useT`:
 * `const et = useApiErrorT(); et('apiError.details.summary')`.
 */
export function useApiErrorT(): (key: ApiErrorCopyKey, params?: TParams) => string {
  const copy = useApiErrorCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}

/**
 * The headline sentence for an error, resolved and interpolated in one step — the common case for a
 * surface that only needs the copy. `params` carries integers only (see {@link ALLOWED_PLACEHOLDERS}).
 */
export function useApiErrorHeadline(): (
  error: ApiErrorLike | null | undefined,
  params?: TParams,
) => string {
  const copy = useApiErrorCopy();
  return useMemo(
    () => (error, params) => interpolate(copy[resolveApiError(error).key], params),
    [copy],
  );
}

/**
 * Non-React resolution, for code outside the component tree (an error mapper, a toast helper).
 * The locale is passed explicitly so this stays a pure function.
 */
export function apiErrorCopy(
  error: ApiErrorLike | null | undefined,
  locale: string,
  params?: TParams,
): string {
  const copy = locale === 'pt-PT' ? apiErrorPtPT : apiErrorEnglish;
  return interpolate(copy[resolveApiError(error).key], params);
}
