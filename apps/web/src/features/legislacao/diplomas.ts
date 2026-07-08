/**
 * The Legislação law shelf (t24) — a curated, typed inventory of the diplomas that
 * ground the product, drawn from the statutory-anchors table in
 * `spec/02-legal-compliance.md` §2. Each entry carries a short faithful extract of the
 * key provision, an editorial note tying it to the app feature it grounds, and stable
 * official links (DRE ELI / EUR-Lex) plus, where an official PDF exists, a `pdfUrl` — the
 * seed for the local "mini law archive" (t27 downloads + digest-pins these into
 * `CHANCELA_DATA_DIR/laws/`; this module stays the curation source of truth).
 *
 * ## Legal-accuracy bar (UX-21)
 * `extractKind` distinguishes a **verbatim quote** from a **resumo**:
 *  - `'quote'` — the `extract` reproduces the official provision text word-for-word.
 *    Used ONLY where the exact official wording is known with confidence (the two
 *    canonical, widely-published EU provisions below). Rendered as a quotation.
 *  - `'resumo'` — the `extract` faithfully *describes* the provision in the app's own
 *    words, WITHOUT quotation marks and flagged "resumo". Never a paraphrase dressed up
 *    as law.
 * The official publication in the Diário da República / EUR-Lex always prevails; the
 * shelf is informative.
 *
 * Official URLs were verified against diariodarepublica.pt / eur-lex.europa.eu on the
 * `REVIEWED_ON` date; the two CAE PDF URLs are the immutable DR "files." artifacts
 * reused verbatim from `crates/chancela-cae/data/source/PROVENANCE.md`.
 */

/** The date this shelf's contents and links were last reviewed. */
export const REVIEWED_ON = '2026-07-07';

/** Thematic groupings, in display order, matching the product's feature areas. */
export const LEGISLACAO_TEMAS = [
  { id: 'atas-sociedades', label: 'Atas e sociedades' },
  { id: 'condominio', label: 'Condomínio' },
  { id: 'assinaturas-confianca', label: 'Assinaturas e confiança' },
  { id: 'cae', label: 'CAE' },
  { id: 'protecao-dados', label: 'Proteção de dados' },
  { id: 'associacoes-fundacoes', label: 'Associações e fundações' },
  { id: 'registo-identificacao', label: 'Registo e identificação' },
] as const;

export type LegislacaoTema = (typeof LEGISLACAO_TEMAS)[number]['id'];

/** Whether an extract is reproduced verbatim (`quote`) or faithfully described (`resumo`). */
export type ExtractKind = 'quote' | 'resumo';

export interface Diploma {
  /** Stable slug, used as the React key and in tests. */
  id: string;
  /** Human-facing title of the diploma / provision. */
  title: string;
  /** The diploma reference (e.g. "CSC, art. 63.º", "Regulamento (UE) 910/2014"). */
  ref: string;
  /** Which thematic shelf this diploma sits on. */
  tema: LegislacaoTema;
  /** One editorial sentence tying the diploma to the app feature it grounds. */
  why: string;
  /** A short faithful extract — verbatim when `extractKind === 'quote'`, else a resumo. */
  extract: string;
  /** `'quote'` = word-for-word; `'resumo'` = faithful description (no quotation marks). */
  extractKind: ExtractKind;
  /** Stable official landing page (DRE ELI consolidated/detalhe, or EUR-Lex). */
  officialUrl: string;
  /**
   * The official PDF of the diploma where one exists — an immutable DR `files.` artifact
   * (original publication) or the EUR-Lex CELEX PDF for the EU regulations; `null` for the
   * consolidated codes (CSC/Código Civil articles) that the DR exposes only as HTML. This
   * is the source URL the local law archive downloads and digest-pins.
   */
  pdfUrl: string | null;
  /** The amending diploma where the shelf records one (e.g. Lei 8/2022); else null. */
  lastAmended: string | null;
  /** The date this entry was last reviewed. */
  reviewedOn: string;
}

/**
 * The curated diplomas. Ordered within each theme roughly by legal weight / reading order.
 */
export const DIPLOMAS: Diploma[] = [
  // ── Atas e sociedades (Código das Sociedades Comerciais + escrituração) ──────────
  {
    id: 'csc-63',
    title: 'Ata das deliberações dos sócios — conteúdo mínimo',
    ref: 'CSC, art. 63.º',
    tema: 'atas-sociedades',
    why: 'Fundamenta o motor de conformidade: o rule-pack do art. 63.º verifica, antes de selar, que a ata reúne o conteúdo mínimo legal.',
    extract:
      'As deliberações dos sócios só podem ser provadas pelas atas das assembleias ou, quando a lei o admita, pelos documentos de onde constem. A ata deve conter a identificação da sociedade, o lugar, dia e hora da reunião, o nome do presidente e, havendo-os, dos secretários, os nomes dos sócios presentes ou representados, a ordem do dia, a referência aos documentos e relatórios apresentados, o teor das deliberações tomadas, os resultados das votações e as declarações cuja inserção tenha sido requerida. Estabelece ainda precauções contra a falsificação nas atas lavradas em folhas soltas; as deliberações que constem apenas de documento particular avulso valem como mero começo de prova.',
    extractKind: 'resumo',
    officialUrl:
      'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975-67019323',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-376',
    title: 'Assembleia geral anual — prazo (sociedades anónimas)',
    ref: 'CSC, art. 376.º',
    tema: 'atas-sociedades',
    why: 'Alimenta os predefinidos do calendário legal — os prazos da assembleia anual derivam desta regra.',
    extract:
      'A assembleia geral anual das sociedades anónimas deve reunir no prazo previsto na lei a contar do encerramento do exercício para apreciar o relatório de gestão e as contas do exercício, deliberar sobre a aplicação de resultados e proceder à apreciação geral da administração e da fiscalização da sociedade.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-377',
    title: 'Convocação da assembleia e reuniões por meios telemáticos',
    ref: 'CSC, art. 377.º',
    tema: 'atas-sociedades',
    why: 'Sustenta a reunião telemática como canal de primeira classe e a prova que o motor recolhe quando o canal é «Telemático».',
    extract:
      'Regula a convocação da assembleia geral — forma, antecedência e menções obrigatórias do aviso convocatório — e admite a realização da assembleia por meios telemáticos, desde que a sociedade assegure a autenticidade das declarações, a segurança das comunicações e o registo do seu conteúdo e dos intervenientes.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-388',
    title: 'Ata obrigatória por cada assembleia geral (sociedades anónimas)',
    ref: 'CSC, art. 388.º',
    tema: 'atas-sociedades',
    why: 'Ancora o ciclo de vida do livro: a cada reunião da assembleia corresponde uma ata no respetivo livro.',
    extract:
      'Nas sociedades anónimas, de cada assembleia geral é lavrada uma ata, assinada por quem nela exerceu as funções de presidente e de secretário da mesa; a lei prevê mecanismos supletivos para os casos em que a ata não possa ser assinada ou aprovada pela forma regular.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-56-58',
    title: 'Invalidade das deliberações dos sócios',
    ref: 'CSC, arts. 56.º e 58.º',
    tema: 'atas-sociedades',
    why: 'Explica o risco que o motor de conformidade previne — vícios de convocação, de conteúdo ou de procedimento podem tornar a deliberação nula ou anulável.',
    extract:
      'O Código das Sociedades Comerciais comina de nulidade as deliberações dos sócios tomadas em assembleia geral não convocada (salvo assembleia universal), as tomadas por escrito quando a lei o não permita, as que tenham conteúdo não sujeito por natureza a deliberação dos sócios e as ofensivas dos bons costumes ou de preceitos legais imperativos. São anuláveis, quando não sejam nulas, as deliberações que violem a lei ou o contrato, incluindo as viciadas por irregularidades de convocação, de informação ou de procedimento.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-246',
    title: 'Matérias que dependem de deliberação dos sócios (sociedades por quotas)',
    ref: 'CSC, art. 246.º',
    tema: 'atas-sociedades',
    why: 'Delimita as matérias que exigem deliberação dos sócios nas sociedades por quotas — as decisões que o Chancela documenta em ata para este tipo societário.',
    extract:
      'Nas sociedades por quotas, dependem de deliberação dos sócios, além de outras, a designação e a destituição de gerentes, a aprovação do relatório de gestão e das contas do exercício, a atribuição de resultados, a amortização e a aquisição de quotas, a exclusão de sócios, a proposição de ações da sociedade contra gerentes ou sócios e a alteração do contrato de sociedade, bem como a fusão, a cisão, a transformação e a dissolução.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'csc-270a',
    title: 'Sociedade unipessoal por quotas — decisões do sócio único',
    ref: 'CSC, arts. 270.º-A e 270.º-E',
    tema: 'atas-sociedades',
    why: 'Fundamenta o registo das decisões do sócio único, que substituem as deliberações da assembleia geral e são exaradas em ata na sociedade unipessoal por quotas.',
    extract:
      'A sociedade unipessoal por quotas é constituída por um único sócio, pessoa singular ou coletiva, titular da totalidade do capital social. Nestas sociedades, o sócio único exerce as competências das assembleias gerais, podendo designadamente aprovar as contas do exercício; as suas decisões de natureza igual à das deliberações da assembleia geral devem ser registadas em ata por ele assinada.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34443975',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'codigo-comercial-escrituracao',
    title: 'Escrituração mercantil e requisitos dos livros — termo de abertura',
    ref: 'Código Comercial (Carta de Lei de 28 de junho de 1888), escrituração mercantil',
    tema: 'atas-sociedades',
    why: 'É a base histórica do termo de abertura e da numeração e rubrica das folhas que o Chancela reproduz na abertura de cada livro de atas.',
    extract:
      'O Código Comercial impõe a todo o comerciante o dever de ter escrituração mercantil organizada segundo a lei e de arquivar e conservar a correspondência e os livros pelo prazo legal. Prevê requisitos extrínsecos dos livros — designadamente o termo de abertura e de encerramento e a numeração e rubrica das folhas — e requisitos intrínsecos de regularidade da escrita, feita sem espaços em branco, entrelinhas, rasuras nem emendas.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/carta-lei/1888-321492',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'dl-76a-2006',
    title: 'Simplificação da escrituração — só o livro de atas permanece obrigatório',
    ref: 'Decreto-Lei n.º 76-A/2006, de 29 de março',
    tema: 'atas-sociedades',
    why: 'Explica porque o Chancela se centra no livro de atas: é o único livro societário que a lei mantém obrigatório.',
    extract:
      'No quadro da simplificação registral e da desmaterialização, deixou de ser obrigatória a existência e a legalização dos livros de escrituração mercantil — inventário e balanços, diário, razão e copiador — mantendo-se obrigatório apenas o livro de atas; foi igualmente eliminada a obrigatoriedade de legalização dos livros.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/decreto-lei/76-a-2006-620286',
    // Original publication, DR 1.ª série-A N.º 63, 29-03-2006 (immutable DR "files." artifact).
    pdfUrl: 'https://files.dre.pt/1s/2006/03/063a01/00020190.pdf',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── Condomínio ───────────────────────────────────────────────────────────────────
  {
    id: 'dl-268-94',
    title: 'Atas das assembleias de condóminos',
    ref: 'Decreto-Lei n.º 268/94, de 25 de outubro',
    tema: 'condominio',
    why: 'Enquadra o livro de atas de condomínio e as vias de assinatura — qualificada ou manuscrita — que o Chancela suporta para os condomínios.',
    extract:
      'As deliberações das assembleias de condóminos são obrigatoriamente reduzidas a ata, que resume os assuntos essenciais e o resultado de cada votação. A subscrição pode fazer-se por assinatura eletrónica qualificada ou de forma manuscrita, no original ou em documento digitalizado que contenha outras assinaturas; a declaração de concordância enviada por correio eletrónico para o endereço da administração vale como subscrição e é anexada ao original.',
    extractKind: 'resumo',
    officialUrl:
      'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1994-144575382',
    // Original publication, DR 1.ª série N.º 247, 25-10-1994 (immutable DR "files." artifact).
    pdfUrl: 'https://files.dre.pt/1s/1994/10/247a00/64296433.pdf',
    lastAmended: 'Lei n.º 8/2022, de 10 de janeiro',
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'cc-propriedade-horizontal',
    title: 'Propriedade horizontal — assembleia e administração do condomínio',
    ref: 'Código Civil, arts. 1414.º a 1438.º-A',
    tema: 'condominio',
    why: 'Enquadra o regime substantivo do condomínio — a assembleia de condóminos e o administrador — cujas deliberações o Chancela documenta a par do Decreto-Lei n.º 268/94.',
    extract:
      'O Código Civil regula a propriedade horizontal — as frações autónomas, as partes comuns do edifício e os encargos de conservação e fruição — e os órgãos do condomínio: a assembleia dos condóminos e o administrador. Fixa as regras de convocação e de deliberação, os quóruns e as maiorias exigidas consoante a matéria e o valor das deliberações, que o Decreto-Lei n.º 268/94 manda reduzir a ata.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1966-34509075',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── Assinaturas e confiança (eIDAS) ──────────────────────────────────────────────
  {
    id: 'dl-12-2021',
    title: 'Execução do eIDAS na ordem jurídica interna',
    ref: 'Decreto-Lei n.º 12/2021, de 9 de fevereiro',
    tema: 'assinaturas-confianca',
    why: 'Concretiza na ordem jurídica interna o regime eIDAS da assinatura eletrónica qualificada e do selo temporal — a pilha de confiança em que assenta a selagem que o Chancela aplica à ata.',
    extract:
      'Assegura, na ordem jurídica interna, a execução do Regulamento (UE) n.º 910/2014 (eIDAS): a assinatura eletrónica qualificada aposta num documento eletrónico equivale à assinatura manuscrita e faz presumir a identidade e a representação de quem assina, a sua vontade de subscrever e a integridade do documento; os selos temporais qualificados fazem presumir o momento e a integridade a que se referem.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/decreto-lei/12-2021-156848060',
    // Original publication, DR 1.ª série N.º 27, 09-02-2021 (immutable DR "files." artifact).
    pdfUrl: 'https://files.diariodarepublica.pt/1s/2021/02/02700/0000400016.pdf',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'eidas-art-25',
    title: 'Efeitos legais das assinaturas eletrónicas qualificadas',
    ref: 'Regulamento (UE) n.º 910/2014 (eIDAS), art. 25.º, n.º 2',
    tema: 'assinaturas-confianca',
    why: 'É a base europeia da equivalência que sustenta a selagem qualificada: o mesmo efeito jurídico da assinatura manuscrita, reconhecido em toda a UE.',
    extract:
      'A assinatura eletrónica qualificada tem um efeito jurídico equivalente ao de uma assinatura manuscrita.',
    extractKind: 'quote',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32014R0910',
    // The official OJ PDF of the base act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32014R0910',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'eidas2-2024-1183',
    title:
      'Quadro Europeu de Identidade Digital (eIDAS 2.0) e Carteira Europeia de Identidade Digital',
    ref: 'Regulamento (UE) 2024/1183 (altera o Regulamento (UE) n.º 910/2014)',
    tema: 'assinaturas-confianca',
    why: 'Antecipa a evolução da pilha de assinatura do Chancela — a carteira europeia de identidade digital e os novos serviços de confiança qualificados.',
    extract:
      'Altera o Regulamento (UE) n.º 910/2014 para estabelecer o Quadro Europeu de Identidade Digital, criando a Carteira Europeia de Identidade Digital que os Estados-Membros devem disponibilizar para a identificação eletrónica e a partilha segura de atributos e documentos. Introduz novos serviços de confiança qualificados — o arquivo eletrónico, os livros-razão eletrónicos e a gestão de dispositivos de criação de assinaturas e selos eletrónicos à distância.',
    extractKind: 'resumo',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32024R1183',
    // The official OJ PDF of the amending act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32024R1183',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── CAE ──────────────────────────────────────────────────────────────────────────
  {
    id: 'dl-9-2025',
    title: 'Classificação Portuguesa das Atividades Económicas, Rev.4 (CAE-Rev.4)',
    ref: 'Decreto-Lei n.º 9/2025, de 12 de fevereiro',
    tema: 'cae',
    why: 'É a fonte legal da tabela CAE-Rev.4 — a revisão em vigor — que o explorador e a validação de CAE usam por omissão.',
    extract:
      'Aprova a Classificação Portuguesa das Atividades Económicas, Revisão 4 (CAE-Rev.4), em vigor desde 1 de janeiro de 2025 e harmonizada com a NACE-Rev.2.1, substituindo a CAE-Rev.3. A classificação organiza-se em cinco níveis, sendo o quinto a subclasse, identificada por um código de cinco dígitos.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/decreto-lei/9-2025-907097147',
    pdfUrl: 'https://files.diariodarepublica.pt/1s/2025/02/03000/0000800049.pdf',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'dl-381-2007',
    title: 'Classificação Portuguesa das Actividades Económicas, Rev.3 (CAE-Rev.3)',
    ref: 'Decreto-Lei n.º 381/2007, de 14 de novembro',
    tema: 'cae',
    why: 'É a fonte legal do catálogo CAE-Rev.3 que o Chancela incorpora e disponibiliza no explorador para códigos anteriores a 2025.',
    extract:
      'Aprova a Classificação Portuguesa das Actividades Económicas, Revisão 3 (CAE-Rev.3), que vigorou de 1 de janeiro de 2008 a 31 de dezembro de 2024, harmonizada com a NACE-Rev.2 e estruturada em secções, divisões, grupos, classes e subclasses.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/decreto-lei/381-2007-629150',
    pdfUrl: 'https://files.dre.pt/1s/2007/11/21900/0844008464.pdf',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── Proteção de dados (RGPD) ─────────────────────────────────────────────────────
  {
    id: 'rgpd-art-5',
    title: 'Princípios do tratamento — minimização dos dados',
    ref: 'RGPD (Regulamento (UE) 2016/679), art. 5.º, n.º 1, al. c)',
    tema: 'protecao-dados',
    why: 'O princípio da minimização orienta o que o Chancela recolhe e conserva — apenas os dados necessários ao registo e à prova.',
    extract:
      'Adequados, pertinentes e limitados ao que é necessário relativamente às finalidades para as quais são tratados («minimização dos dados»).',
    extractKind: 'quote',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32016R0679',
    // The official OJ PDF of the base act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32016R0679',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'rgpd-art-25',
    title: 'Proteção de dados desde a conceção e por defeito',
    ref: 'RGPD, art. 25.º',
    tema: 'protecao-dados',
    why: 'Sustenta a arquitetura de privacidade «by design» do Chancela — isolamento por entidade, âmbito de acesso e retenção configurável.',
    extract:
      'Impõe a proteção de dados desde a conceção e por defeito: o responsável aplica medidas técnicas e organizativas adequadas — como a pseudonimização e a minimização — tanto na definição dos meios de tratamento como durante o próprio tratamento, garantindo que, por defeito, apenas são tratados os dados necessários para cada finalidade.',
    extractKind: 'resumo',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32016R0679',
    // The official OJ PDF of the base act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32016R0679',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'rgpd-art-32',
    title: 'Segurança do tratamento',
    ref: 'RGPD, art. 32.º',
    tema: 'protecao-dados',
    why: 'Enquadra a cifragem, a integridade selada e a capacidade de restauro após incidente que a arquitetura do Chancela assegura.',
    extract:
      'Exige medidas de segurança do tratamento adequadas ao risco, incluindo, consoante o caso, a cifragem e a pseudonimização, a capacidade de assegurar a confidencialidade, a integridade, a disponibilidade e a resiliência dos sistemas, e a capacidade de restabelecer a disponibilidade e o acesso aos dados na sequência de um incidente.',
    extractKind: 'resumo',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32016R0679',
    // The official OJ PDF of the base act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32016R0679',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'rgpd-art-35',
    title: 'Avaliação de impacto sobre a proteção de dados (AIPD)',
    ref: 'RGPD, art. 35.º',
    tema: 'protecao-dados',
    why: 'Fundamenta o modelo de AIPD que acompanha as implementações do Chancela em cenários de tratamento de risco elevado.',
    extract:
      'Quando um tratamento, em especial pela utilização de novas tecnologias, seja suscetível de implicar um risco elevado para os direitos e liberdades das pessoas singulares, o responsável procede, previamente, a uma avaliação de impacto das operações de tratamento sobre a proteção dos dados pessoais.',
    extractKind: 'resumo',
    officialUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/?uri=CELEX:32016R0679',
    // The official OJ PDF of the base act (EUR-Lex CELEX PDF endpoint).
    pdfUrl: 'https://eur-lex.europa.eu/legal-content/PT/TXT/PDF/?uri=CELEX:32016R0679',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  {
    id: 'lei-58-2019',
    title: 'Execução do RGPD na ordem jurídica nacional',
    ref: 'Lei n.º 58/2019, de 8 de agosto',
    tema: 'protecao-dados',
    why: 'Complementa o RGPD com as regras nacionais — competências da CNPD, prazos de conservação e certificação — que enquadram o tratamento de dados no Chancela em Portugal.',
    extract:
      'Assegura a execução, na ordem jurídica nacional, do Regulamento (UE) 2016/679 (RGPD). Designa a Comissão Nacional de Proteção de Dados (CNPD) como autoridade de controlo nacional, regula o encarregado de proteção de dados, as condições do consentimento e os prazos de conservação, prevê a certificação e a emissão de selos e marcas de proteção de dados por organismos acreditados e define o regime sancionatório aplicável em território nacional.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/detalhe/lei/58-2019-123815982',
    // Original publication, DR 1.ª série N.º 151, 08-08-2019 (immutable DR "files." artifact).
    pdfUrl: 'https://files.dre.pt/1s/2019/08/15100/0000300040.pdf',
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── Associações e fundações ──────────────────────────────────────────────────────
  {
    id: 'codigo-civil-pessoas-coletivas',
    title: 'Associações e fundações como pessoas coletivas de direito privado',
    ref: 'Código Civil (associações e fundações)',
    tema: 'associacoes-fundacoes',
    why: 'Enquadra as associações e fundações como entidades que o Chancela suporta, cujas assembleias e órgãos produzem atas.',
    extract:
      'O Código Civil regula as pessoas coletivas de direito privado — associações e fundações — designadamente a sua constituição, os órgãos, o funcionamento das assembleias e a extinção; as suas deliberações são documentadas em ata.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1966-34509075',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'cc-associacoes',
    title: 'Associações — órgãos, assembleia geral e deliberações',
    ref: 'Código Civil, arts. 157.º a 184.º',
    tema: 'associacoes-fundacoes',
    why: 'Fundamenta o funcionamento das associações que o Chancela suporta — a assembleia geral, a sua convocação e as maiorias cujas deliberações se documentam em ata.',
    extract:
      'O Código Civil regula as associações sem fim lucrativo — a sua constituição por escritura ou por documento com reconhecimento de assinaturas, os estatutos, e os órgãos: a assembleia geral, a administração e o conselho fiscal. Fixa as competências da assembleia geral, as regras da sua convocação e as maiorias exigidas — incluindo as maiorias qualificadas para alterar os estatutos e para dissolver a associação.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1966-34509075',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'lei-24-2012',
    title: 'Lei-Quadro das Fundações',
    ref: 'Lei n.º 24/2012, de 9 de julho',
    tema: 'associacoes-fundacoes',
    why: 'Complementa o Código Civil no suporte às fundações — reconhecimento, registo e funcionamento — que o Chancela contempla.',
    extract:
      'Estabelece os princípios e as normas por que se regem as fundações — nacionais e estrangeiras que prossigam os seus fins em território nacional — incluindo o reconhecimento, o registo e as regras de organização e funcionamento.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/lei/2012-61239015',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },

  // ── Registo e identificação ──────────────────────────────────────────────────────
  {
    id: 'crcom-403-86',
    title: 'Código do Registo Comercial — publicidade dos atos societários',
    ref: 'Código do Registo Comercial (Decreto-Lei n.º 403/86, de 3 de dezembro)',
    tema: 'registo-identificacao',
    why: 'Enquadra o destino registal dos atos que o Chancela documenta — muitas deliberações estão sujeitas a registo comercial para produzirem efeitos perante terceiros.',
    extract:
      'O registo comercial destina-se a dar publicidade à situação jurídica dos comerciantes individuais, das sociedades comerciais e civis sob forma comercial e de outras entidades a ele sujeitas, tendo em vista a segurança do comércio jurídico. Estão sujeitos a registo, entre outros factos, a constituição, as alterações do contrato ou do estatuto e diversas deliberações sociais; os factos sujeitos a registo só produzem efeitos perante terceiros depois da data do respetivo registo.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1986-34444675',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'dl-129-98-rnpc',
    title: 'Registo Nacional de Pessoas Coletivas e o NIPC',
    ref: 'Decreto-Lei n.º 129/98, de 13 de maio (regime do RNPC)',
    tema: 'registo-identificacao',
    why: 'Fundamenta a validação do NIPC e a admissibilidade da firma ou denominação que o Chancela aplica ao identificar cada entidade.',
    extract:
      'Aprova o regime do Registo Nacional de Pessoas Coletivas, que organiza e gere o ficheiro central de pessoas coletivas, aprecia a admissibilidade de firmas e denominações e atribui o número de identificação de pessoa coletiva (NIPC). Cada pessoa coletiva ou entidade equiparada é identificada por um NIPC, que consta do respetivo cartão de identificação e a acompanha nas suas relações jurídicas.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/decreto-lei/1998-34526475',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
  {
    id: 'lei-89-2017-rcbe',
    title: 'Registo Central do Beneficiário Efetivo (RCBE)',
    ref: 'Lei n.º 89/2017, de 21 de agosto',
    tema: 'registo-identificacao',
    why: 'Sustenta o dever de manter atualizada a informação sobre o beneficiário efetivo — relevante sempre que uma deliberação registada altera a titularidade ou o controlo da entidade.',
    extract:
      'Aprova o Regime Jurídico do Registo Central do Beneficiário Efetivo, transpondo o capítulo III da Diretiva (UE) 2015/849. As entidades abrangidas devem declarar e manter atualizada a identificação das pessoas singulares que, ainda que de forma indireta ou através de terceiro, detêm a propriedade ou o controlo efetivo da entidade, conservando essa informação suficiente, exata e atual.',
    extractKind: 'resumo',
    officialUrl: 'https://diariodarepublica.pt/dr/legislacao-consolidada/lei/1900-108031925',
    pdfUrl: null,
    lastAmended: null,
    reviewedOn: REVIEWED_ON,
  },
];

/** The diplomas on a given theme, in inventory order. */
export function diplomasByTema(tema: LegislacaoTema): Diploma[] {
  return DIPLOMAS.filter((d) => d.tema === tema);
}

/**
 * Case- and accent-folded text for the Legislação search: NFD-decompose, strip the
 * combining diacritic marks, lowercase. So "Condomínio", "condominio" and
 * "CONDOMÍNIO" fold equal, and a query typed without accents still matches accented
 * content (and vice-versa). No such helper existed (the CAE explorer searches server-side),
 * so this is the shared folder for the shelf's client-side filter.
 */
export function foldForSearch(text: string): string {
  return text
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase();
}

/** The folded haystack for a diploma — everything the search looks inside. */
function diplomaHaystack(d: Diploma): string {
  return foldForSearch(`${d.title} ${d.ref} ${d.why} ${d.extract}`);
}

/**
 * The diplomas whose title, reference, why-note or extract contain the (accent-and-case-
 * folded) query, in inventory order. A blank query returns the whole shelf.
 */
export function searchDiplomas(query: string): Diploma[] {
  const q = foldForSearch(query.trim());
  if (q.length === 0) return DIPLOMAS;
  return DIPLOMAS.filter((d) => diplomaHaystack(d).includes(q));
}
