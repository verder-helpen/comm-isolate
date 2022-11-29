use lazy_static;
use rocket::{
    response::{self, content, Responder},
    Request,
};
use std::path::Path;
use tera::Tera;

#[derive(PartialEq, Eq)]
pub struct RenderedContent {
    pub content: String,
    pub render_type: RenderType,
}

#[cfg(test)]
impl RenderedContent {
    pub fn content(&self) -> &str {
        &self.content
    }
}

impl<'r> Responder<'r, 'static> for RenderedContent {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        let RenderedContent {
            content,
            render_type,
        } = self;
        if render_type == RenderType::Json {
            return content::RawJson(content).respond_to(req);
        }
        content::RawHtml(content).respond_to(req)
    }
}

#[derive(PartialEq, Eq)]
pub enum RenderType {
    Json,
    Html,
    HtmlPage,
}

// Includes template at runtime, if available, otherwise uses compile-time template. This enables the option to override
// the templates per comm-plugin, but also to simply use the default template.
macro_rules! include_template {
    ($tera:ident, $template_name:literal) => {
        if Path::new(concat!("templates/", $template_name)).exists() {
            $tera
                .add_template_file(concat!("templates/", $template_name), Some($template_name))
                .expect(concat!(
                    "Error loading custom ",
                    $template_name,
                    " template"
                ));
        } else {
            $tera
                .add_raw_template(
                    $template_name,
                    include_str!(concat!("templates/", $template_name)),
                )
                .expect(concat!(
                    "Error loading included ",
                    $template_name,
                    " template"
                ));
        }
    };
}

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = Tera::default();

        include_template!(tera, "base.html");
        include_template!(tera, "credentials.html");
        include_template!(tera, "login.html");
        include_template!(tera, "expired.html");
        include_template!(tera, "not_found.html");

        tera
    };
}
