use zorq_acl::*;

fn main() -> Result<(), Error> {
    env_logger::init();

    let mut acl = Acl::new();

    acl.add_role("guest", vec![])?;
    acl.add_role("staff", vec!["guest"])?;
    acl.add_role("editor", vec!["staff"])?;
    acl.add_role("admin", vec![])?;

    // guest may only view content
    acl.allow(Some("guest"), None, Some("view"))?;

    // staff inherits view privilege from guest, but also needs additional privileges
    acl.allow(Some("staff"), None, Some("edit"))?;
    acl.allow(Some("staff"), None, Some("submit"))?;
    acl.allow(Some("staff"), None, Some("revise"))?;

    // editor inherits view, edit, submit, and revise privileges from staff, but also needs
    // additional privileges
    acl.allow(Some("editor"), None, Some("publish"))?;
    acl.allow(Some("editor"), None, Some("archive"))?;
    acl.allow(Some("editor"), None, Some("delete"))?;

    // admin inherits nothing, but is allowed all privileges
    acl.allow(Some("admin"), None, None)?;

    // marketing inherits from staff
    acl.add_role("marketing", vec!["staff"])?;

    acl.add_resource("newsletter", None)?;
    acl.add_resource("news", None)?;
    acl.add_resource("latest", Some("news"))?;
    acl.add_resource("anouncement", Some("news"))?;

    // marketing must be able to publish and archive newsletters and the latest news
    acl.allow(Some("marketing"), Some("newsletter"), Some("publish"))?;
    acl.allow(Some("marketing"), Some("latest"), Some("archive"))?;

    // staff (and marketing, by inheritance), are denied permission to revise the latest news
    acl.deny(Some("staff"), Some("latest"), Some("revise"))?;
    
    // everyone (including admins) are denied permission to archive news announcements
    acl.deny(None, Some("anouncement"), Some("archive"))?;

    Ok(())
 } // main