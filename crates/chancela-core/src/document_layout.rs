//! Deterministic, author-safe document layout policy.
//!
//! The concrete [`DocumentLayoutPolicy`] is the complete set of values a renderer consumes.
//! Instance settings own that concrete base. Templates, entities, and books carry
//! [`DocumentLayoutOverrides`], whose leaves are all optional: an absent leaf means “inherit”.
//! [`resolve_document_layout`] merges those layers field-by-field in the fixed precedence order
//! instance → template → entity → book and records which layer supplied every effective value.
//!
//! Values use integer millimetres, points, and percentages. Besides producing a friendly JSON
//! contract, this avoids floating-point equality and serialization drift in the frozen document
//! model. Conversion to PDF points belongs to the renderer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Smallest supported page content width after margins.
pub const MIN_USABLE_PAGE_WIDTH_MM: u16 = 90;
/// Smallest supported page content height after margins.
pub const MIN_USABLE_PAGE_HEIGHT_MM: u16 = 100;

const MIN_MARGIN_MM: u16 = 5;
const MAX_MARGIN_MM: u16 = 60;
const MIN_BODY_FONT_SIZE_PT: u16 = 8;
const MAX_BODY_FONT_SIZE_PT: u16 = 18;
const MIN_HEADER_FONT_SIZE_PT: u16 = 8;
const MAX_HEADER_FONT_SIZE_PT: u16 = 24;
const MIN_FOOTER_FONT_SIZE_PT: u16 = 7;
const MAX_FOOTER_FONT_SIZE_PT: u16 = 16;
const MIN_LINE_SPACING_PERCENT: u16 = 100;
const MAX_LINE_SPACING_PERCENT: u16 = 200;
const MAX_PARAGRAPH_SPACING_PT: u16 = 24;
const MIN_HEADING_SCALE_PERCENT: u16 = 75;
const MAX_HEADING_SCALE_PERCENT: u16 = 200;
const MAX_REGION_GAP_MM: u16 = 30;

/// Supported physical page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentPageSize {
    /// ISO A4: 210 × 297 mm.
    A4,
    /// ISO A5: 148 × 210 mm.
    A5,
    /// North-American Letter: 216 × 279 mm, rounded to whole millimetres.
    Letter,
    /// North-American Legal: 216 × 356 mm, rounded to whole millimetres.
    Legal,
}

impl DocumentPageSize {
    /// Portrait width and height, in whole millimetres.
    #[must_use]
    pub const fn dimensions_mm(self) -> (u16, u16) {
        match self {
            Self::A4 => (210, 297),
            Self::A5 => (148, 210),
            Self::Letter => (216, 279),
            Self::Legal => (216, 356),
        }
    }
}

/// Physical page orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentOrientation {
    /// The page size's shorter dimension is its width.
    Portrait,
    /// Width and height are swapped; renderers need not add a PDF `/Rotate`.
    Landscape,
}

/// Renderer-owned, approved embedded font families.
///
/// Arbitrary font names and paths are intentionally impossible to express: every selected face
/// must be bundled, embedded, and covered by the renderer's PDF/A self-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentFontFamily {
    /// Bundled Noto Serif.
    NotoSerif,
    /// Bundled Noto Sans.
    NotoSans,
}

/// Concrete page geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPageLayout {
    /// Physical page size.
    pub size: DocumentPageSize,
    /// Physical page orientation.
    pub orientation: DocumentOrientation,
    /// Content margins, in whole millimetres.
    pub margins_mm: DocumentPageMargins,
}

/// Concrete page margins, in whole millimetres.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPageMargins {
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
    pub left: u16,
}

/// Concrete typography controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentTypography {
    pub body_font_family: DocumentFontFamily,
    pub body_font_size_pt: u16,
    pub header_font_family: DocumentFontFamily,
    pub header_font_size_pt: u16,
    pub footer_font_family: DocumentFontFamily,
    pub footer_font_size_pt: u16,
    pub line_spacing_percent: u16,
    pub paragraph_spacing_pt: u16,
    pub heading_scale_percent: u16,
}

/// Concrete spacing between document regions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRegions {
    pub header_gap_mm: u16,
    pub footer_gap_mm: u16,
}

/// Complete renderer input after inheritance has been resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentLayoutPolicy {
    pub page: DocumentPageLayout,
    pub typography: DocumentTypography,
    pub regions: DocumentRegions,
}

impl Default for DocumentLayoutPolicy {
    /// Product defaults corresponding to the existing deterministic writer: A4 portrait,
    /// approximately 20 mm margins, Noto Serif, 10 pt body, and 140% leading.
    fn default() -> Self {
        Self {
            page: DocumentPageLayout {
                size: DocumentPageSize::A4,
                orientation: DocumentOrientation::Portrait,
                margins_mm: DocumentPageMargins {
                    top: 20,
                    right: 20,
                    bottom: 20,
                    left: 20,
                },
            },
            typography: DocumentTypography {
                body_font_family: DocumentFontFamily::NotoSerif,
                body_font_size_pt: 10,
                header_font_family: DocumentFontFamily::NotoSerif,
                header_font_size_pt: 11,
                footer_font_family: DocumentFontFamily::NotoSerif,
                footer_font_size_pt: 9,
                line_spacing_percent: 140,
                paragraph_spacing_pt: 6,
                heading_scale_percent: 100,
            },
            regions: DocumentRegions {
                header_gap_mm: 4,
                footer_gap_mm: 4,
            },
        }
    }
}

impl DocumentLayoutPolicy {
    /// Whether this is exactly the product policy. Useful for backward-compatible omission from
    /// older wire models while keeping the in-memory value concrete.
    #[must_use]
    pub fn is_product_default(&self) -> bool {
        self == &Self::default()
    }

    /// Oriented physical page width and height, in millimetres.
    #[must_use]
    pub const fn page_dimensions_mm(&self) -> (u16, u16) {
        let (width, height) = self.page.size.dimensions_mm();
        match self.page.orientation {
            DocumentOrientation::Portrait => (width, height),
            DocumentOrientation::Landscape => (height, width),
        }
    }

    /// Usable content width and height after margins, when the geometry is non-negative.
    #[must_use]
    pub fn usable_page_dimensions_mm(&self) -> Option<(u16, u16)> {
        let (width, height) = self.page_dimensions_mm();
        let horizontal =
            u32::from(self.page.margins_mm.left) + u32::from(self.page.margins_mm.right);
        let vertical = u32::from(self.page.margins_mm.top) + u32::from(self.page.margins_mm.bottom);
        let usable_width = u32::from(width).checked_sub(horizontal)?;
        let usable_height = u32::from(height).checked_sub(vertical)?;
        Some((
            u16::try_from(usable_width).ok()?,
            u16::try_from(usable_height).ok()?,
        ))
    }

    /// Validate every numeric range and the resulting usable page geometry.
    pub fn validate(&self) -> Result<(), DocumentLayoutValidationError> {
        validate_margin(DocumentLayoutField::MarginTopMm, self.page.margins_mm.top)?;
        validate_margin(
            DocumentLayoutField::MarginRightMm,
            self.page.margins_mm.right,
        )?;
        validate_margin(
            DocumentLayoutField::MarginBottomMm,
            self.page.margins_mm.bottom,
        )?;
        validate_margin(DocumentLayoutField::MarginLeftMm, self.page.margins_mm.left)?;
        validate_typography(&self.typography)?;
        validate_range(
            DocumentLayoutField::HeaderGapMm,
            self.regions.header_gap_mm,
            0,
            MAX_REGION_GAP_MM,
        )?;
        validate_range(
            DocumentLayoutField::FooterGapMm,
            self.regions.footer_gap_mm,
            0,
            MAX_REGION_GAP_MM,
        )?;

        let (page_width_mm, page_height_mm) = self.page_dimensions_mm();
        let Some((usable_width_mm, usable_height_mm)) = self.usable_page_dimensions_mm() else {
            return Err(DocumentLayoutValidationError::UnusablePage {
                page_width_mm,
                page_height_mm,
                usable_width_mm: 0,
                usable_height_mm: 0,
                minimum_width_mm: MIN_USABLE_PAGE_WIDTH_MM,
                minimum_height_mm: MIN_USABLE_PAGE_HEIGHT_MM,
            });
        };
        if usable_width_mm < MIN_USABLE_PAGE_WIDTH_MM
            || usable_height_mm < MIN_USABLE_PAGE_HEIGHT_MM
        {
            return Err(DocumentLayoutValidationError::UnusablePage {
                page_width_mm,
                page_height_mm,
                usable_width_mm,
                usable_height_mm,
                minimum_width_mm: MIN_USABLE_PAGE_WIDTH_MM,
                minimum_height_mm: MIN_USABLE_PAGE_HEIGHT_MM,
            });
        }
        Ok(())
    }
}

/// Optional page geometry leaves. Missing means inherited.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DocumentPageLayoutOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<DocumentPageSize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<DocumentOrientation>,
    #[serde(skip_serializing_if = "DocumentPageMarginsOverrides::is_empty")]
    pub margins_mm: DocumentPageMarginsOverrides,
}

impl DocumentPageLayoutOverrides {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size.is_none() && self.orientation.is_none() && self.margins_mm.is_empty()
    }
}

/// Optional page-margin leaves. Missing means inherited.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DocumentPageMarginsOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottom: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<u16>,
}

impl DocumentPageMarginsOverrides {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.top.is_none() && self.right.is_none() && self.bottom.is_none() && self.left.is_none()
    }
}

/// Optional typography leaves. Missing means inherited.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DocumentTypographyOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_font_family: Option<DocumentFontFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_font_size_pt: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_font_family: Option<DocumentFontFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_font_size_pt: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer_font_family: Option<DocumentFontFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer_font_size_pt: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_spacing_percent: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paragraph_spacing_pt: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heading_scale_percent: Option<u16>,
}

impl DocumentTypographyOverrides {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.body_font_family.is_none()
            && self.body_font_size_pt.is_none()
            && self.header_font_family.is_none()
            && self.header_font_size_pt.is_none()
            && self.footer_font_family.is_none()
            && self.footer_font_size_pt.is_none()
            && self.line_spacing_percent.is_none()
            && self.paragraph_spacing_pt.is_none()
            && self.heading_scale_percent.is_none()
    }
}

/// Optional region-spacing leaves. Missing means inherited.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DocumentRegionsOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_gap_mm: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer_gap_mm: Option<u16>,
}

impl DocumentRegionsOverrides {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.header_gap_mm.is_none() && self.footer_gap_mm.is_none()
    }
}

/// One inheritable layout layer. Every leaf is optional and defaults to inheritance.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DocumentLayoutOverrides {
    #[serde(skip_serializing_if = "DocumentPageLayoutOverrides::is_empty")]
    pub page: DocumentPageLayoutOverrides,
    #[serde(skip_serializing_if = "DocumentTypographyOverrides::is_empty")]
    pub typography: DocumentTypographyOverrides,
    #[serde(skip_serializing_if = "DocumentRegionsOverrides::is_empty")]
    pub regions: DocumentRegionsOverrides,
}

impl DocumentLayoutOverrides {
    /// Whether this layer overrides no field.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.page.is_empty() && self.typography.is_empty() && self.regions.is_empty()
    }

    /// Validate all values present in this layer. Cross-field usable-page validation happens after
    /// resolution, because omitted dimensions intentionally come from lower-precedence layers.
    pub fn validate(&self) -> Result<(), DocumentLayoutValidationError> {
        if let Some(value) = self.page.margins_mm.top {
            validate_margin(DocumentLayoutField::MarginTopMm, value)?;
        }
        if let Some(value) = self.page.margins_mm.right {
            validate_margin(DocumentLayoutField::MarginRightMm, value)?;
        }
        if let Some(value) = self.page.margins_mm.bottom {
            validate_margin(DocumentLayoutField::MarginBottomMm, value)?;
        }
        if let Some(value) = self.page.margins_mm.left {
            validate_margin(DocumentLayoutField::MarginLeftMm, value)?;
        }
        validate_optional_typography(&self.typography)?;
        if let Some(value) = self.regions.header_gap_mm {
            validate_range(
                DocumentLayoutField::HeaderGapMm,
                value,
                0,
                MAX_REGION_GAP_MM,
            )?;
        }
        if let Some(value) = self.regions.footer_gap_mm {
            validate_range(
                DocumentLayoutField::FooterGapMm,
                value,
                0,
                MAX_REGION_GAP_MM,
            )?;
        }
        Ok(())
    }
}

/// A leaf in the layout contract, used as the stable key of the provenance map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLayoutField {
    PageSize,
    PageOrientation,
    MarginTopMm,
    MarginRightMm,
    MarginBottomMm,
    MarginLeftMm,
    BodyFontFamily,
    BodyFontSizePt,
    HeaderFontFamily,
    HeaderFontSizePt,
    FooterFontFamily,
    FooterFontSizePt,
    LineSpacingPercent,
    ParagraphSpacingPt,
    HeadingScalePercent,
    HeaderGapMm,
    FooterGapMm,
}

impl DocumentLayoutField {
    /// Every field, in stable document order.
    pub const ALL: [Self; 17] = [
        Self::PageSize,
        Self::PageOrientation,
        Self::MarginTopMm,
        Self::MarginRightMm,
        Self::MarginBottomMm,
        Self::MarginLeftMm,
        Self::BodyFontFamily,
        Self::BodyFontSizePt,
        Self::HeaderFontFamily,
        Self::HeaderFontSizePt,
        Self::FooterFontFamily,
        Self::FooterFontSizePt,
        Self::LineSpacingPercent,
        Self::ParagraphSpacingPt,
        Self::HeadingScalePercent,
        Self::HeaderGapMm,
        Self::FooterGapMm,
    ];
}

/// Layer that supplied one effective leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentLayoutSource {
    Instance,
    Template,
    Entity,
    Book,
}

/// Concrete policy plus provenance for every leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDocumentLayout {
    pub policy: DocumentLayoutPolicy,
    pub sources: BTreeMap<DocumentLayoutField, DocumentLayoutSource>,
}

impl ResolvedDocumentLayout {
    /// The source of `field`; every value produced by [`resolve_document_layout`] has all fields.
    #[must_use]
    pub fn source(&self, field: DocumentLayoutField) -> Option<DocumentLayoutSource> {
        self.sources.get(&field).copied()
    }
}

/// A numeric or cross-field policy failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocumentLayoutValidationError {
    /// A numeric leaf fell outside its bounded authoring range.
    #[error("{field:?} must be between {minimum} and {maximum}, got {actual}")]
    OutOfRange {
        field: DocumentLayoutField,
        minimum: u16,
        maximum: u16,
        actual: u16,
    },
    /// Page size/orientation/margins leave too little usable content area.
    #[error(
        "page {page_width_mm}x{page_height_mm} mm leaves only \
         {usable_width_mm}x{usable_height_mm} mm usable; at least \
         {minimum_width_mm}x{minimum_height_mm} mm is required"
    )]
    UnusablePage {
        page_width_mm: u16,
        page_height_mm: u16,
        usable_width_mm: u16,
        usable_height_mm: u16,
        minimum_width_mm: u16,
        minimum_height_mm: u16,
    },
}

/// Resolve instance → template → entity → book field-by-field.
///
/// The instance base must be concrete. Missing override layers and missing leaves inherit. Every
/// supplied layer is range-checked before application and the final page geometry is validated
/// after all precedence has been applied.
pub fn resolve_document_layout(
    instance: &DocumentLayoutPolicy,
    template: Option<&DocumentLayoutOverrides>,
    entity: Option<&DocumentLayoutOverrides>,
    book: Option<&DocumentLayoutOverrides>,
) -> Result<ResolvedDocumentLayout, DocumentLayoutValidationError> {
    instance.validate()?;
    let mut policy = instance.clone();
    let mut sources = DocumentLayoutField::ALL
        .into_iter()
        .map(|field| (field, DocumentLayoutSource::Instance))
        .collect::<BTreeMap<_, _>>();

    for (overrides, source) in [
        (template, DocumentLayoutSource::Template),
        (entity, DocumentLayoutSource::Entity),
        (book, DocumentLayoutSource::Book),
    ] {
        if let Some(overrides) = overrides {
            overrides.validate()?;
            apply_overrides(&mut policy, &mut sources, overrides, source);
        }
    }
    policy.validate()?;
    Ok(ResolvedDocumentLayout { policy, sources })
}

fn apply_overrides(
    policy: &mut DocumentLayoutPolicy,
    sources: &mut BTreeMap<DocumentLayoutField, DocumentLayoutSource>,
    overrides: &DocumentLayoutOverrides,
    source: DocumentLayoutSource,
) {
    macro_rules! apply {
        ($override:expr, $target:expr, $field:expr) => {
            if let Some(value) = $override {
                $target = value;
                sources.insert($field, source);
            }
        };
    }

    apply!(
        overrides.page.size,
        policy.page.size,
        DocumentLayoutField::PageSize
    );
    apply!(
        overrides.page.orientation,
        policy.page.orientation,
        DocumentLayoutField::PageOrientation
    );
    apply!(
        overrides.page.margins_mm.top,
        policy.page.margins_mm.top,
        DocumentLayoutField::MarginTopMm
    );
    apply!(
        overrides.page.margins_mm.right,
        policy.page.margins_mm.right,
        DocumentLayoutField::MarginRightMm
    );
    apply!(
        overrides.page.margins_mm.bottom,
        policy.page.margins_mm.bottom,
        DocumentLayoutField::MarginBottomMm
    );
    apply!(
        overrides.page.margins_mm.left,
        policy.page.margins_mm.left,
        DocumentLayoutField::MarginLeftMm
    );
    apply!(
        overrides.typography.body_font_family,
        policy.typography.body_font_family,
        DocumentLayoutField::BodyFontFamily
    );
    apply!(
        overrides.typography.body_font_size_pt,
        policy.typography.body_font_size_pt,
        DocumentLayoutField::BodyFontSizePt
    );
    apply!(
        overrides.typography.header_font_family,
        policy.typography.header_font_family,
        DocumentLayoutField::HeaderFontFamily
    );
    apply!(
        overrides.typography.header_font_size_pt,
        policy.typography.header_font_size_pt,
        DocumentLayoutField::HeaderFontSizePt
    );
    apply!(
        overrides.typography.footer_font_family,
        policy.typography.footer_font_family,
        DocumentLayoutField::FooterFontFamily
    );
    apply!(
        overrides.typography.footer_font_size_pt,
        policy.typography.footer_font_size_pt,
        DocumentLayoutField::FooterFontSizePt
    );
    apply!(
        overrides.typography.line_spacing_percent,
        policy.typography.line_spacing_percent,
        DocumentLayoutField::LineSpacingPercent
    );
    apply!(
        overrides.typography.paragraph_spacing_pt,
        policy.typography.paragraph_spacing_pt,
        DocumentLayoutField::ParagraphSpacingPt
    );
    apply!(
        overrides.typography.heading_scale_percent,
        policy.typography.heading_scale_percent,
        DocumentLayoutField::HeadingScalePercent
    );
    apply!(
        overrides.regions.header_gap_mm,
        policy.regions.header_gap_mm,
        DocumentLayoutField::HeaderGapMm
    );
    apply!(
        overrides.regions.footer_gap_mm,
        policy.regions.footer_gap_mm,
        DocumentLayoutField::FooterGapMm
    );
}

fn validate_margin(
    field: DocumentLayoutField,
    value: u16,
) -> Result<(), DocumentLayoutValidationError> {
    validate_range(field, value, MIN_MARGIN_MM, MAX_MARGIN_MM)
}

fn validate_typography(
    typography: &DocumentTypography,
) -> Result<(), DocumentLayoutValidationError> {
    validate_range(
        DocumentLayoutField::BodyFontSizePt,
        typography.body_font_size_pt,
        MIN_BODY_FONT_SIZE_PT,
        MAX_BODY_FONT_SIZE_PT,
    )?;
    validate_range(
        DocumentLayoutField::HeaderFontSizePt,
        typography.header_font_size_pt,
        MIN_HEADER_FONT_SIZE_PT,
        MAX_HEADER_FONT_SIZE_PT,
    )?;
    validate_range(
        DocumentLayoutField::FooterFontSizePt,
        typography.footer_font_size_pt,
        MIN_FOOTER_FONT_SIZE_PT,
        MAX_FOOTER_FONT_SIZE_PT,
    )?;
    validate_range(
        DocumentLayoutField::LineSpacingPercent,
        typography.line_spacing_percent,
        MIN_LINE_SPACING_PERCENT,
        MAX_LINE_SPACING_PERCENT,
    )?;
    validate_range(
        DocumentLayoutField::ParagraphSpacingPt,
        typography.paragraph_spacing_pt,
        0,
        MAX_PARAGRAPH_SPACING_PT,
    )?;
    validate_range(
        DocumentLayoutField::HeadingScalePercent,
        typography.heading_scale_percent,
        MIN_HEADING_SCALE_PERCENT,
        MAX_HEADING_SCALE_PERCENT,
    )
}

fn validate_optional_typography(
    typography: &DocumentTypographyOverrides,
) -> Result<(), DocumentLayoutValidationError> {
    for (field, value, minimum, maximum) in [
        (
            DocumentLayoutField::BodyFontSizePt,
            typography.body_font_size_pt,
            MIN_BODY_FONT_SIZE_PT,
            MAX_BODY_FONT_SIZE_PT,
        ),
        (
            DocumentLayoutField::HeaderFontSizePt,
            typography.header_font_size_pt,
            MIN_HEADER_FONT_SIZE_PT,
            MAX_HEADER_FONT_SIZE_PT,
        ),
        (
            DocumentLayoutField::FooterFontSizePt,
            typography.footer_font_size_pt,
            MIN_FOOTER_FONT_SIZE_PT,
            MAX_FOOTER_FONT_SIZE_PT,
        ),
        (
            DocumentLayoutField::LineSpacingPercent,
            typography.line_spacing_percent,
            MIN_LINE_SPACING_PERCENT,
            MAX_LINE_SPACING_PERCENT,
        ),
        (
            DocumentLayoutField::ParagraphSpacingPt,
            typography.paragraph_spacing_pt,
            0,
            MAX_PARAGRAPH_SPACING_PT,
        ),
        (
            DocumentLayoutField::HeadingScalePercent,
            typography.heading_scale_percent,
            MIN_HEADING_SCALE_PERCENT,
            MAX_HEADING_SCALE_PERCENT,
        ),
    ] {
        if let Some(value) = value {
            validate_range(field, value, minimum, maximum)?;
        }
    }
    Ok(())
}

fn validate_range(
    field: DocumentLayoutField,
    value: u16,
    minimum: u16,
    maximum: u16,
) -> Result<(), DocumentLayoutValidationError> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(DocumentLayoutValidationError::OutOfRange {
            field,
            minimum,
            maximum,
            actual: value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_default_matches_the_existing_writer_contract() {
        let policy = DocumentLayoutPolicy::default();
        assert_eq!(policy.page.size, DocumentPageSize::A4);
        assert_eq!(policy.page.orientation, DocumentOrientation::Portrait);
        assert_eq!(
            policy.page.margins_mm,
            DocumentPageMargins {
                top: 20,
                right: 20,
                bottom: 20,
                left: 20,
            }
        );
        assert_eq!(
            policy.typography.body_font_family,
            DocumentFontFamily::NotoSerif
        );
        assert_eq!(policy.typography.body_font_size_pt, 10);
        assert_eq!(policy.typography.line_spacing_percent, 140);
        assert_eq!(policy.usable_page_dimensions_mm(), Some((170, 257)));
        policy.validate().expect("product policy is valid");
    }

    #[test]
    fn empty_override_serializes_as_an_empty_object_and_means_inherit() {
        let overrides = DocumentLayoutOverrides::default();
        assert!(overrides.is_empty());
        assert_eq!(
            serde_json::to_value(&overrides).expect("serializes"),
            serde_json::json!({})
        );
        let back: DocumentLayoutOverrides =
            serde_json::from_str("{}").expect("empty override deserializes");
        assert_eq!(back, overrides);
    }

    #[test]
    fn partial_override_serializes_only_authored_leaves() {
        let overrides = DocumentLayoutOverrides {
            page: DocumentPageLayoutOverrides {
                orientation: Some(DocumentOrientation::Landscape),
                ..Default::default()
            },
            typography: DocumentTypographyOverrides {
                body_font_size_pt: Some(12),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&overrides).expect("serializes"),
            serde_json::json!({
                "page": {"orientation": "Landscape"},
                "typography": {"body_font_size_pt": 12}
            })
        );
    }

    #[test]
    fn font_family_names_are_stable_and_allowlisted() {
        assert_eq!(
            serde_json::to_string(&DocumentFontFamily::NotoSerif).unwrap(),
            "\"NotoSerif\""
        );
        assert_eq!(
            serde_json::to_string(&DocumentFontFamily::NotoSans).unwrap(),
            "\"NotoSans\""
        );
        assert!(
            serde_json::from_str::<DocumentFontFamily>("\"ComicSans\"").is_err(),
            "arbitrary fonts must not enter the policy"
        );
    }

    #[test]
    fn resolver_applies_every_layer_per_leaf_and_records_provenance() {
        let instance = DocumentLayoutPolicy::default();
        let template = DocumentLayoutOverrides {
            typography: DocumentTypographyOverrides {
                body_font_family: Some(DocumentFontFamily::NotoSans),
                body_font_size_pt: Some(12),
                ..Default::default()
            },
            ..Default::default()
        };
        let entity = DocumentLayoutOverrides {
            page: DocumentPageLayoutOverrides {
                orientation: Some(DocumentOrientation::Landscape),
                margins_mm: DocumentPageMarginsOverrides {
                    left: Some(25),
                    ..Default::default()
                },
                ..Default::default()
            },
            typography: DocumentTypographyOverrides {
                body_font_size_pt: Some(13),
                header_font_family: Some(DocumentFontFamily::NotoSans),
                ..Default::default()
            },
            ..Default::default()
        };
        let book = DocumentLayoutOverrides {
            page: DocumentPageLayoutOverrides {
                margins_mm: DocumentPageMarginsOverrides {
                    left: Some(15),
                    bottom: Some(18),
                    ..Default::default()
                },
                ..Default::default()
            },
            regions: DocumentRegionsOverrides {
                footer_gap_mm: Some(8),
                ..Default::default()
            },
            ..Default::default()
        };

        let resolved =
            resolve_document_layout(&instance, Some(&template), Some(&entity), Some(&book))
                .expect("valid cascade");
        assert_eq!(
            resolved.policy.typography.body_font_family,
            DocumentFontFamily::NotoSans
        );
        assert_eq!(resolved.policy.typography.body_font_size_pt, 13);
        assert_eq!(
            resolved.policy.typography.header_font_family,
            DocumentFontFamily::NotoSans
        );
        assert_eq!(
            resolved.policy.page.orientation,
            DocumentOrientation::Landscape
        );
        assert_eq!(resolved.policy.page.margins_mm.left, 15);
        assert_eq!(resolved.policy.page.margins_mm.right, 20);
        assert_eq!(resolved.policy.page.margins_mm.bottom, 18);
        assert_eq!(resolved.policy.regions.footer_gap_mm, 8);

        assert_eq!(
            resolved.source(DocumentLayoutField::BodyFontFamily),
            Some(DocumentLayoutSource::Template)
        );
        assert_eq!(
            resolved.source(DocumentLayoutField::BodyFontSizePt),
            Some(DocumentLayoutSource::Entity)
        );
        assert_eq!(
            resolved.source(DocumentLayoutField::PageOrientation),
            Some(DocumentLayoutSource::Entity)
        );
        assert_eq!(
            resolved.source(DocumentLayoutField::MarginLeftMm),
            Some(DocumentLayoutSource::Book)
        );
        assert_eq!(
            resolved.source(DocumentLayoutField::MarginRightMm),
            Some(DocumentLayoutSource::Instance)
        );
        assert_eq!(
            resolved.source(DocumentLayoutField::FooterGapMm),
            Some(DocumentLayoutSource::Book)
        );
        assert_eq!(resolved.sources.len(), DocumentLayoutField::ALL.len());
    }

    #[test]
    fn absent_layers_leave_every_value_and_source_at_instance() {
        let instance = DocumentLayoutPolicy::default();
        let resolved =
            resolve_document_layout(&instance, None, None, None).expect("default resolves");
        assert_eq!(resolved.policy, instance);
        for field in DocumentLayoutField::ALL {
            assert_eq!(
                resolved.source(field),
                Some(DocumentLayoutSource::Instance),
                "{field:?}"
            );
        }
    }

    #[test]
    fn override_range_validation_is_strict_before_resolution() {
        let overrides = DocumentLayoutOverrides {
            typography: DocumentTypographyOverrides {
                line_spacing_percent: Some(99),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            overrides.validate(),
            Err(DocumentLayoutValidationError::OutOfRange {
                field: DocumentLayoutField::LineSpacingPercent,
                minimum: 100,
                maximum: 200,
                actual: 99,
            })
        );
        assert!(
            resolve_document_layout(
                &DocumentLayoutPolicy::default(),
                Some(&overrides),
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn resolved_geometry_must_leave_a_usable_page() {
        let overrides = DocumentLayoutOverrides {
            page: DocumentPageLayoutOverrides {
                size: Some(DocumentPageSize::A5),
                margins_mm: DocumentPageMarginsOverrides {
                    left: Some(30),
                    right: Some(30),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let error = resolve_document_layout(
            &DocumentLayoutPolicy::default(),
            None,
            None,
            Some(&overrides),
        )
        .expect_err("88 mm is narrower than the supported layout profile");
        assert!(matches!(
            error,
            DocumentLayoutValidationError::UnusablePage {
                usable_width_mm: 88,
                ..
            }
        ));
    }

    #[test]
    fn page_orientation_swaps_dimensions_without_rotate_semantics() {
        let mut policy = DocumentLayoutPolicy::default();
        assert_eq!(policy.page_dimensions_mm(), (210, 297));
        policy.page.orientation = DocumentOrientation::Landscape;
        assert_eq!(policy.page_dimensions_mm(), (297, 210));
        assert_eq!(policy.usable_page_dimensions_mm(), Some((257, 170)));
        policy.validate().expect("A4 landscape is valid");
    }

    #[test]
    fn strict_policy_and_override_json_reject_unknown_fields() {
        let mut policy = serde_json::to_value(DocumentLayoutPolicy::default()).unwrap();
        policy
            .as_object_mut()
            .unwrap()
            .insert("raw_pdf".to_owned(), serde_json::json!("unsafe"));
        assert!(serde_json::from_value::<DocumentLayoutPolicy>(policy).is_err());
        assert!(
            serde_json::from_value::<DocumentLayoutOverrides>(serde_json::json!({
                "typography": {"font_path": "C:/private/font.ttf"}
            }))
            .is_err()
        );
    }

    #[test]
    fn entity_and_book_overrides_round_trip_and_default_to_inheritance() {
        let mut entity = crate::Entity::new(
            "Encosto Estratégico Lda",
            crate::Nipc::unvalidated("500123456"),
            "Lisboa",
            crate::EntityKind::SociedadePorQuotas,
        );
        let mut book = crate::Book::new(entity.id, crate::BookKind::AssembleiaGeral);
        assert!(entity.document_layout_override.is_none());
        assert!(book.document_layout_override.is_none());

        let overrides = DocumentLayoutOverrides {
            typography: DocumentTypographyOverrides {
                body_font_family: Some(DocumentFontFamily::NotoSans),
                ..Default::default()
            },
            ..Default::default()
        };
        entity.document_layout_override = Some(overrides.clone());
        book.document_layout_override = Some(overrides);

        let entity_json = serde_json::to_string(&entity).expect("entity serializes");
        let book_json = serde_json::to_string(&book).expect("book serializes");
        assert!(entity_json.contains("\"document_layout_override\""));
        assert!(book_json.contains("\"document_layout_override\""));
        let entity_back: crate::Entity =
            serde_json::from_str(&entity_json).expect("entity deserializes");
        let book_back: crate::Book = serde_json::from_str(&book_json).expect("book deserializes");
        assert_eq!(entity_back, entity);
        assert_eq!(book_back, book);
    }
}
