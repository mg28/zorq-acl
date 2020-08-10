//! Lightweigth and flexible access control list (ACL) implementation for privilege management.
//! 
//! This is an adoption of the [laminas-permissions-acl](https://docs.laminas.dev/laminas-permissions-acl/usage/)
//! to Rust. The following documentation is a copy and adoption of the original documentation of
//! *"Laminas\Permissions\Acl\Acl"*. See file CREDITS for copyright notices on behalf of the Laminas
//! project.
//! 
//! # What is missing from the original implementation?
//! 
//! * Removing access control. This will be implemented in a future version by a `revoke` method.
//! * Ownership assertions and the role and resource interfaces. Ownership assertion may be
//! implemented by traits defining the role and resource interface and by extending the api in
//! the future.
//! * Expression assertions. This may be implemented in a future version.
//! 
//! # Introduction
//! 
//! In general an appilcation can utilize ACLs to allow or deny access to resources by requesting
//! objects.
//! 
//! In the sense of this implementation:
//! * a *resource* is an object to which access is controlled.
//! * a *role* is an object that may request access to a resource.
//! * a *privilage* is an action which may be granted on a resource to a role.
//! 
//! ## Resources
//! 
//! Resources are organized in a tree strcuture and must be named uniquely. Since resources are
//! stored in such a tree structure, they can be oragnized from the general (tree root) to the
//! specific (tree leafs). Queries on a specific resource will automatically search the resource's
//! hierarchy for rules assigned to ancestor resources, allowing for simple inheritance of rules.
//! For example, if a default rule is to be applied to each building in a city, one would simply
//! assign the rule to the city, instead of assigning the same rule to each building. Some buildings
//! may require exceptions to such a rule, however, by assigning such exception rules to each
//! building that requires such an exception. A resource may inherit from only one parent resource,
//! though this parent resource can have its own parent resource, etc.
//! 
//! Privileges on resources (e.g., "create", "read", "update", "delete") are also supported, so one
//! can assign rules that affect all privileges or specific privileges on one or more resources.
//! 
//! ## Roles
//!
//! A role may inherit from one or more roles. This is to support inheritance of rules among roles.
//! For example, a user role, such as "sally", may belong to one or more parent roles, such as
//! "editor" and "administrator". The developer can assign rules to "editor" and "administrator"
//! separately, and "sally" would inherit such rules from both, without having to assign rules directly
//! to "sally".
//!
//! Though the ability to inherit from multiple roles is very useful, multiple inheritance also
//! introduces some degree of complexity. The following example illustrates the ambiguity condition
//! and how `Acl` solves it.
//! 
//! ### Multiple Inheritance among Roles
//! 
//! The following code defines three base roles - "guest", "member", and "admin" - from which other
//! roles may inherit. Then, a role identified by "someUser" is established and inherits from the
//! three other roles. The order in which these roles appear in the `parents` array is important.
//! When necessary, searches for access include not only rules defined for the queried role (herein,
//! "someUser"), but also upon the roles from which the queried role inherits (herein, "guest",
//! "member", and "admin"):
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! acl.add_role("guest", vec![]);
//! acl.add_role("member", vec![]);
//! acl.add_role("admin", vec![]);
//! 
//! let parents = vec!["guest", "member", "admin"];
//! 
//! acl.add_role("someUser", parents);
//! acl.add_resource("someResource", None);
//! 
//! acl.deny(Some("guest"), Some("someResource"), None);
//! acl.allow(Some("member"), Some("someResource"), None);
//! 
//! assert!(acl.is_allowed(Some("someUser"), Some("someResource"), None));
//! ```
//! 
//! Since there is no rule specifically defined for the "someUser" role and "someResource", the `Acl`
//! must search for rules that may be defined for roles that "someUser" inherits. First, the "admin"
//! role is visited, and there is no access rule defined for it. Next, the "member" role is visited,
//! and the `Acl` finds that there is a rule specifying that "member" is allowed access to
//! "someResource".
//!
//! If the `Acl` were to continue examining the rules defined for other parent roles, however, it would
//! find that "guest" is denied access to "someResource". This fact introduces an ambiguity because now
//! "someUser" is both denied and allowed access to "someResource", by reason of having inherited
//! conflicting rules from different parent roles.
//!
//! The `Acl` resolves this ambiguity by completing a query when it finds the first rule that is
//! directly applicable to the query. In this case, since the "member" role is examined before the
//! "guest" role, the example code assertion is met and hence access is allowed.
//! 
//! > *LIFO Order for Role Queries*:
//! > When specifying multiple parents for a role, keep in mind that the last parent listed is the first
//! > one searched for rules applicable to an authorization query.
//! 
//! # Creating the Access Control List
//! 
//! An Access Control List (ACL) can represent any set of physical or virtual objects that you wish.
//! For the purposes of demonstration, however, we will create a basic Content Management System (CMS)
//! ACL that maintains several tiers of groups over a wide variety of areas. To create a new ACL object,
//! we instantiate the ACL. The constructor has no parameters:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! use zorq_acl::Acl;
//! 
//! let mut acl = Acl::new();
//! ```
//! 
//! ## Denied by default
//! 
//! Until a developer specifies an "allow" rule, the `Acl` denies access to every privilege upon every
//! resource by every role.
//! 
//! # Registering Roles
//!
//! CMS systems will nearly always require a hierarchy of permissions to determine the authoring
//! capabilities of its users. There may be a 'Guest' group to allow limited access for demonstrations,
//! a 'Staff' group for the majority of CMS users who perform most of the day-to-day operations, an
//! 'Editor' group for those responsible for publishing, reviewing, archiving and deleting content,
//! and finally an 'Administrator' group whose tasks may include all of those of the other groups as
//! well as maintenance of sensitive information, user management, back-end configuration data,
//! backup and export. This set of permissions can be represented in a role registry, allowing each
//! group to inherit privileges from 'parent' groups, as well as providing distinct privileges for
//! their unique group only. The permissions may be expressed as follows:
//! 
//! <table>
//! <tr><th>Name</th>          <th>Unique Permissions</th>       <th>Inherit Permissions From</th></tr>
//! <tr><td>Guest</td>         <td>View</td>                     <td>N/A</td></tr>
//! <tr><td>Staff</td>         <td>Edit, Submit, Revise</td>     <td>Guest</td></tr>
//! <tr><td>Editor</td>        <td>Publish, Archive, Delete</td> <td>Staff</td></tr>
//! <tr><td>Administrator</td> <td>(Granted all access)</td>     <td>N/A</td></tr>
//! </table>
//! 
//! These groups can be added to the role registry as follows:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! acl.add_role("guest", vec![]);
//! acl.add_role("staff", vec!["guest"]);
//! acl.add_role("editor", vec!["staff"]);
//! acl.add_role("admin", vec![]);
//! ```
//! 
//! # Defining Access Controls
//!
//! Now that the ACL contains the relevant roles, rules can be established that define how resources
//! may be accessed by roles. You may have noticed that we have not defined any particular resources
//! for this example, which is simplified to illustrate that the rules apply to all resources. The
//! `Acl` provides an implementation whereby rules need only be assigned from general to specific,
//! minimizing the number of rules needed, because resources and roles inherit rules that are defined
//! upon their ancestors.
//! 
//! > *Specificity*:
//! > In general, the `Acl` obeys a given rule if and only if a more specific rule does not apply.
//! 
//! Consequently, we can define a reasonably complex set of rules with a minimum amount of code.
//! To apply the base permissions as defined above:
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! # acl.add_role("guest", vec![]);
//! # acl.add_role("staff", vec!["guest"]);
//! # acl.add_role("editor", vec!["staff"]);
//! # acl.add_role("admin", vec![]);
//! // guest may only view content
//! acl.allow(Some("guest"), None, Some("view"));
//!
//! // staff inherits view privilege from guest, but also needs additional privileges
//! acl.allow(Some("staff"), None, Some("edit"));
//! acl.allow(Some("staff"), None, Some("submit"));
//! acl.allow(Some("staff"), None, Some("revise"));
//!
//! // editor inherits view, edit, submit, and revise privileges from staff, but also needs
//! // additional privileges
//! acl.allow(Some("editor"), None, Some("publish"));
//! acl.allow(Some("editor"), None, Some("archive"));
//! acl.allow(Some("editor"), None, Some("delete"));
//!
//! // admin inherits nothing, but is allowed all privileges
//! acl.allow(Some("admin"), None, None);
//! ```
//! 
//! The `None` values in the above `allow()` calls are used to indicate that the allow rules apply
//! to all resources. `None` is equal to a wildcard.
//! 
//! # Querying an ACL
//!
//! We now have a flexible ACL that can be used to determine whether requesters have permission to
//! perform functions throughout the web application. Performing queries is quite simple using the
//! `is_allowed` or `is_denied` method:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! # acl.add_role("guest", vec![]);
//! # acl.add_role("staff", vec!["guest"]);
//! # acl.add_role("editor", vec!["staff"]);
//! # acl.add_role("admin", vec![]);
//! # acl.allow(Some("guest"), None, Some("view"));
//! # acl.allow(Some("staff"), None, Some("edit"));
//! # acl.allow(Some("staff"), None, Some("submit"));
//! # acl.allow(Some("staff"), None, Some("revise"));
//! # acl.allow(Some("editor"), None, Some("publish"));
//! # acl.allow(Some("editor"), None, Some("archive"));
//! # acl.allow(Some("editor"), None, Some("delete"));
//! # acl.allow(Some("admin"), None, None);
//! // allowed
//! assert!( acl.is_allowed(Some("guest"), None, Some("view")));
//! assert!(!acl.is_denied (Some("guest"), None, Some("view")));
//!
//! // denied
//! assert!(!acl.is_allowed(Some("staff"), None, Some("publish")));
//! assert!( acl.is_denied (Some("staff"), None, Some("publish")));
//!
//! // allowed
//! assert!( acl.is_allowed(Some("staff"), None, Some("revise")));
//! assert!(!acl.is_denied (Some("staff"), None, Some("revise")));
//!
//! // allowed because of inheritance from guest
//! assert!( acl.is_allowed(Some("editor"), None, Some("view")));
//! assert!(!acl.is_denied (Some("editor"), None, Some("view")));
//!
//! // denied because no allow rule for 'update'
//! assert!(!acl.is_allowed(Some("editor"), None, Some("update")));
//! assert!( acl.is_denied (Some("editor"), None, Some("update")));
//!
//! // allowed because admin is allowed all privileges
//! assert!( acl.is_allowed(Some("admin"), None, Some("view")));
//! assert!(!acl.is_denied (Some("admin"), None, Some("view")));
//!
//! // allowed because admin is allowed all privileges
//! assert!( acl.is_allowed(Some("admin"), None, None));
//! assert!(!acl.is_denied (Some("admin"), None, None));
//!
//! // allowed because admin is allowed all privileges
//! assert!( acl.is_allowed(Some("admin"), None, Some("update")));
//! assert!(!acl.is_denied (Some("admin"), None, Some("update")));
//! ```
//! 
//! # Precise Access Controls
//!
//! The basic ACL as defined in the previous section shows how various privileges may be allowed
//! upon the entire ACL (all resources). In practice, however, access controls tend to have
//! exceptions and varying degrees of complexity. The `Acl` allows you to accomplish these
//! refinements in a straightforward and flexible manner.
//!
//! For the example CMS, it has been determined that whilst the 'staff' group covers the needs of
//! the vast majority of users, there is a need for a new 'marketing' group that requires access
//! to the newsletter and latest news in the CMS. The group is fairly self-sufficient and will
//! have the ability to publish and archive both newsletters and the latest news.
//!
//! In addition, it has also been requested that the 'staff' group be allowed to view news stories
//! but not to revise the latest news. Finally, it should be impossible for anyone (administrators
//! included) to archive any 'announcement' news stories since they only have a lifespan of 1-2 days.
//!
//! First we revise the role registry to reflect these changes. We have determined that the
//! 'marketing' group has the same basic permissions as 'staff', so we define 'marketing' in such a
//! way that it inherits permissions from 'staff':
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! # acl.add_role("guest", vec![]);
//! # acl.add_role("staff", vec!["guest"]);
//! # acl.add_role("editor", vec!["staff"]);
//! # acl.add_role("admin", vec![]);
//! acl.add_role("marketing", vec!["staff"]);
//! ```
//! Next, note that the above access controls refer to specific resources (e.g., "newsletter",
//! "latest news", "announcement news"). Now we add these resources:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! acl.add_resource("newsletter", None);
//! acl.add_resource("news", None);
//! acl.add_resource("latest", Some("news"));
//! acl.add_resource("anouncement", Some("news"));
//! ```
//! 
//! Then it is simply a matter of defining these more specific rules on the target areas of the ACL:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! # acl.add_role("guest", vec![]);
//! # acl.add_role("staff", vec!["guest"]);
//! # acl.add_role("editor", vec!["staff"]);
//! # acl.add_role("admin", vec![]);
//! # acl.add_role("marketing", vec!["staff"]);
//! # acl.add_resource("newsletter", None);
//! # acl.add_resource("news", None);
//! # acl.add_resource("latest", Some("news"));
//! # acl.add_resource("anouncement", Some("news"));
//! // marketing must be able to publish and archive newsletters and the latest news
//! acl.allow(Some("marketing"), Some("newsletter"), Some("publish"));
//! acl.allow(Some("marketing"), Some("newsletter"), Some("archive"));
//! acl.allow(Some("marketing"), Some("latest"), Some("publish"));
//! acl.allow(Some("marketing"), Some("latest"), Some("archive"));
//!
//! // staff (and marketing, by inheritance), are denied permission
//! // to revise the latest news
//! acl.deny(Some("staff"), Some("latest"), Some("revise"));
//!
//! // everyone (including admins) are denied permission to archive news announcements
//! acl.deny(None, Some("anouncement"), Some("archive"));
//! ```
//! 
//! We can now query the ACL with respect to the latest changes:
//! 
//! ```rust
//! # extern crate zorq_acl;
//! # use zorq_acl::Acl;
//! # let mut acl = Acl::new();
//! # acl.add_role("guest", vec![]);
//! # acl.add_role("staff", vec!["guest"]);
//! # acl.add_role("editor", vec!["staff"]);
//! # acl.add_role("admin", vec![]);
//! # acl.allow(Some("guest"), None, Some("view"));
//! # acl.allow(Some("staff"), None, Some("edit"));
//! # acl.allow(Some("staff"), None, Some("submit"));
//! # acl.allow(Some("staff"), None, Some("revise"));
//! # acl.allow(Some("editor"), None, Some("publish"));
//! # acl.allow(Some("editor"), None, Some("archive"));
//! # acl.allow(Some("editor"), None, Some("delete"));
//! # acl.allow(Some("admin"), None, None);
//! # acl.add_role("marketing", vec!["staff"]);
//! # acl.add_resource("newsletter", None);
//! # acl.add_resource("news", None);
//! # acl.add_resource("latest", Some("news"));
//! # acl.add_resource("anouncement", Some("news"));
//! # acl.allow(Some("marketing"), Some("newsletter"), Some("publish"));
//! # acl.allow(Some("marketing"), Some("newsletter"), Some("archive"));
//! # acl.allow(Some("marketing"), Some("latest"), Some("publish"));
//! # acl.allow(Some("marketing"), Some("latest"), Some("archive"));
//! # acl.deny(Some("staff"), Some("latest"), Some("revise"));
//! # acl.deny(None, Some("anouncement"), Some("archive"));
//! // denied
//! assert!(!acl.is_allowed(Some("staff"), Some("newsletter"), Some("publish")));
//! assert!( acl.is_denied (Some("staff"), Some("newsletter"), Some("publish")));
//!
//! // allowed
//! assert!( acl.is_allowed(Some("marketing"), Some("newsletter"), Some("publish")));
//! assert!(!acl.is_denied (Some("marketing"), Some("newsletter"), Some("publish")));
//!
//! // denied
//! assert!(!acl.is_allowed(Some("staff"), Some("latest"), Some("publish")));
//! assert!( acl.is_denied (Some("staff"), Some("latest"), Some("publish")));
//!
//! // allowed
//! assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("publish")));
//! assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("publish")));
//!
//! // allowed
//! assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("archive")));
//! assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("archive")));
//!
//! // denied
//! assert!(!acl.is_allowed(Some("marketing"), Some("latest"), Some("revise")));
//! assert!( acl.is_denied (Some("marketing"), Some("latest"), Some("revise")));
//!
//! // denied
//! assert!(!acl.is_allowed(Some("editor"), Some("anouncement"), Some("archive")));
//! assert!( acl.is_denied (Some("editor"), Some("anouncement"), Some("archive")));
//!
//! // denied
//! assert!(!acl.is_allowed(Some("admin"), Some("anouncement"), Some("archive")));
//! assert!( acl.is_denied (Some("admin"), Some("anouncement"), Some("archive")));
//! ```

use log::{trace, warn};
use std::cell::RefCell;
use std::fmt;
use std::hash::Hash;
use std::ops::Index;
use std::collections::{BTreeMap, HashMap, HashSet};


// Helper types ///////////////////////////////////////////////////////////////////////////////////


type Resource   = Option<&'static str>;
type Role       = Option<&'static str>;
type Roles      = Option<Vec<&'static str>>;
type Privilege  = Option<&'static str>;

/// Allow or deny access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Allow,
    Deny
} // enum Access

/// Defines if a privilege is allowed or denied for a role on a resource. The selective parameters
/// are in decending order of precedence: resource, role and privilege.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rule {
    // the granted access: allow or deny
    acc: Access,
} // struct Rule


// Query //////////////////////////////////////////////////////////////////////////////////////////


/// Defines the parameters to query a rule for. A None value for a parameter declares a wildcard
/// placeholder.
#[derive(Debug, Eq, Hash, PartialEq)]
struct Query {
    pub resource:  Option<&'static str>,
    pub role:      Option<&'static str>,
    pub privilege: Option<&'static str>,
} // Query

impl Query {

    /// This defines the catch all criteria. A rule for this query is always defined in an Acl.
    const ALL: Query = Query{resource: None, role: None, privilege: None};

} // impl Query


// Acl ////////////////////////////////////////////////////////////////////////////////////////////


/// Main structure holding the defined roles, resources, privileges and rules. Roles, resources and
/// privileges are not automatically defined upon rule definition, but must be declared beforehand.
/// A catch-all rule is predefined and denies access. This is like a drop-policy on firewalls.
pub struct Acl {
    resources:  BTreeMap<&'static str, Option<&'static str>>,
    roles:      BTreeMap<&'static str, Vec<&'static str>>,
    rules:      HashMap<Query, Rule>,
    lock:       Option<RefCell<HashMap<Query, Rule>>>,
} // Acl

impl Acl {

    /// Creates a new `Acl`. The `Acl` is unlocked by default. After you defined your rules you may
    /// lock the `Acl` to speed up rule queries. At any point you can unlock the `Acl` and define
    /// new rules. The methods `lock` and `unlock` require mutable access. But remember that
    /// unlocking the `Acl` also purges the cache. In locked state you are still able to add roles,
    /// resources and privileges.
    pub fn new() -> Self {
        trace!("creating new acl");
        let mut acl = Acl{
            resources:  BTreeMap::new(),
            roles:      BTreeMap::new(),
            rules:      HashMap::new(),
            lock:       None,
        }; // Acl

        acl.rules.insert(Query::ALL, Rule{acc: Access::Deny});
        acl
    } // new

    /// Lock prevents defining new rules in order to be able to utilze the rule cache and speed up
    /// rule queries.
    pub fn lock(&mut self) {
        if self.lock.is_none() {
            self.lock = Some(RefCell::new(HashMap::new()))
        } // if
    } // lock

    /// Unlock opens the `Acl` to define new rules and purges and disables the cache.
    pub fn unlock(&mut self) {
        if self.lock.is_some() {
            self.lock = None
        } // if
    } // unlock

    /// Adds a new resource. Returns an error if resource is already defined or parent is unknown.
    pub fn add_resource(&mut self, name: &'static str, parent: Option<&'static str>) -> Result<(), Error> {
        trace!("adding resource {} with parent {:?}", name, parent);
        if self.resources.contains_key(name) {
            warn!("adding duplicate resource: {}", name);
            return Err(Error::DuplicateResource(String::from(name)));
        } // if
        if let Some(name) = parent {
            if !self.resources.contains_key(name) {
                warn!("missing parent for new resource: {}", name);
                return Err(Error::MissingParent(String::from(name)))
            } // if
        } // if
        self.resources.insert(name, parent);
        Ok(())
    } // add_resource

    /// Returns true if resource is defined.
    #[inline]
    pub fn has_resource(&self, name: &'static str) -> bool {
        self.resources.contains_key(name)
    } // has_resource

    /// Returns the parent of resource or None. Returns an error if resource is undefined.
    pub fn get_resource_parent(&self, name: &'static str) -> Result<Option<&'static str>, Error> {
        trace!("getting resource parent for: {}", name);
        if let Some(parent) = self.resources.get(name) {
            return Ok(*parent)
        } // if
        warn!("missing resource while getting parent: {}", name);
        Err(Error::MissingResource(String::from(name)))
    } // get_resource_parent

    /// Returns the ancestors prefixed with the resource. Returns an empty vector if resource is undefined.
    pub fn get_resource_lineage(&self, name: &'static str) -> Vec<&'static str> {
        trace!("getting resource lineage for: {}", name);
        match self.resources.get(name) {
            None         => vec![],
            Some(parent) => {
                let mut v = vec![name];
                let mut i = parent;

                loop {
                    if let Some(name) = i {
                        v.push(name);
                        i = self.resources.get(name).unwrap();
                    } else {
                        break
                    } // else
                } // loop
                v
            }, // Some
        } // match
    } // get_resource_lineage

    /// Returns the ancestors of the resource. Returns an empty vector if resource is undefined.
    pub fn get_resource_ancestors(&self, name: &'static str) -> Vec<&'static str> {
        trace!("getting resource ancestors for: {}", name);
        let lin = self.get_resource_lineage(name);

        if lin.len() > 1 {
            lin[1..].to_vec()
        } else {
            vec![]
        } // else
    } // get_resource_ancestors

    /// Adds a new role. Returns an error if role is already defined or parent is unknown.
    pub fn add_role(&mut self, name: &'static str, parents: Vec<&'static str>) -> Result<(), Error> {
        trace!("adding role {} with parents {:?}", name, parents);
        if self.roles.contains_key(name) {
            warn!("adding duplicate role: {}", name);
            return Err(Error::DuplicateRole(String::from(name)));
        } // if
        if parents.len() > 0 {
            let mut reversed = parents.clone();

            for name in parents {
                if !self.roles.contains_key(name) {
                    warn!("missing parent for new role: {}", name);
                    return Err(Error::MissingParent(String::from(name)))
                } // if
            } // for
            reversed.reverse();
            self.roles.insert(name, reversed);
        } else {
            self.roles.insert(name, vec![]);
        } // else
        Ok(())
    } // add_role

    /// Returns true if role is defined.
    #[inline]
    pub fn has_role(&self, name: &'static str) -> bool {
        self.roles.contains_key(name)
    } // has_role

    /// Returns the parent of role or None. Returns an error if role is undefined.
    pub fn get_role_parents(&self, name: &'static str) -> Result<Vec<&'static str>, Error> {
        trace!("getting role parents for: {}", name);
        if let Some(parent) = self.roles.get(name) {
            return Ok(parent.to_vec())
        } // if
        warn!("missing role while getting parents: {}", name);
        Err(Error::MissingRole(String::from(name)))
    } // get_role_parents

    fn iter_roles(&self, roles: &Vec<&'static str>, seen: &mut HashSet<&'static str>, lineage: &mut Vec<&'static str>) {
        for role in roles {
            // only add this role if we haven't seen it already
            if !seen.contains(role) {
                seen.insert(role);
                lineage.push(role);
            } // if
            if let Some(parents) = self.roles.get(role) {
                if parents.len() > 0 {
                    self.iter_roles(parents, seen, lineage);
                } // if
            } // if
        } // for
    } // iter_roles

    /// Returns the ancestors prefixed with the role. Returns an empty vector if role is undefined.
    pub fn get_role_lineage(&self, name: &'static str) -> Vec<&'static str> {
        trace!("getting role lineage for: {}", name);
        match self.roles.get(name) {
            None         => vec![],
            Some(parents) => {
                let mut seen    = HashSet::new();
                let mut lineage = vec![name];

                if parents.len() > 0 {
                    self.iter_roles(parents, &mut seen, &mut lineage);
                } // if
                lineage
            }, // Some
        } // match
    } // get_role_lineage

    /// Returns the ancestors of the role. Returns an empty vector if role is undefined.
    pub fn get_role_ancestors(&self, name: &'static str) -> Vec<&'static str> {
        trace!("getting role ancestors for: {}", name);
        let lin = self.get_role_lineage(name);

        if lin.len() > 1 {
            lin[1..].to_vec()
        } else {
            vec![]
        } // else
    } // get_role_ancestors

    /// Allows privilege for role on resource. Returns an error if role, resource or privilege is undefined.
    #[inline]
    pub fn allow(&mut self, role: Role, resource: Resource, privilege: Privilege) -> Result<(), Error> {
        self.set_rule(role, resource, privilege, Access::Allow)
    } // allow

    /// Returns true if privilege is allowed for role on resource.
    #[inline]
    pub fn is_allowed(&self, role: Role, resource: Resource, privilege: Privilege) -> bool {
        self.get_rule(role, resource, privilege).acc == Access::Allow
    } // is_allowed

    /// Denies privilege for role on resource. Returns an error if role, resource or privilege is undefined.
    #[inline]
    pub fn deny(&mut self, role: Role, resource: Resource, privilege: Privilege) -> Result<(), Error> {
        self.set_rule(role, resource, privilege, Access::Deny)
    } // deny

    /// Returns true if privilege is denied for role on resource.
    #[inline]
    pub fn is_denied(&self, role: Role, resource: Resource, privilege: Privilege) -> bool {
        self.get_rule(role, resource, privilege).acc == Access::Deny
    } // is_denied

    #[inline]
    fn get_one_rule(&self, role: Role, resource: Resource, privilege: Privilege) -> Option<&Rule> {
        trace!("getting one rule for {:?} on {:?} to {:?}", role, resource, privilege);
        self.rules.get(&Query{resource, role, privilege})
    } // get_one_rule

    fn query_privileges(&self, resource: &Resource, role: &Role, privilege: &Privilege) -> Option<&Rule> {
        // query specific privilege
        if let Some(_) = privilege {
            trace!("querying rule for {:?} on {:?} to {:?}", role, resource, privilege);
            if let Some(rule) = self.get_one_rule(*role, *resource, *privilege) {
                return Some(rule);
            } // if let
        }  // if
        // query wildcard privilage if query isn't equal to Query::ALL
        if resource.is_some() || role.is_some() {
            trace!("querying rule for {:?} on {:?} to None", role, resource);
            return self.get_one_rule(*role, *resource, None);
        } // if
        None
    } // query_privileges

    fn query_roles(&self, resource: &Resource, roles: &Roles, privilege: &Privilege) -> Option<&Rule> {
        // specific roles in lineage
        if let Some(names) = roles {
            for name in names {
                if let Some(rule) = self.query_privileges(resource, &Some(name), privilege) {
                    return Some(rule);
                } // if let
            } // for
        } // if let
        // wildcrad role
        self.query_privileges(resource, &None, privilege)
    } // query_roles

    fn query_precedence(&self, role: Role, resource: Resource, privilege: Privilege) -> Option<&Rule> {
        let resources = if let Some(name) = resource {
            Some(self.get_resource_lineage(name))
        } else { None };
        let roles = if let Some(name) = role {
            Some(self.get_role_lineage(name))
        } else { None };

        // specific resource
        if let Some(names) = resources {
            for name in names {
                if let Some(rule) = self.query_roles(&Some(name), &roles, &privilege) {
                    return Some(rule);
                } // if let
            } // for
        } // if
        // wildcard resource
        self.query_roles(&None, &roles, &privilege)
    } // get_query_precedence

    /// This always returns a rule. If no specific rule is defined by the query, the corresponding
    /// catch-all rule is returned. Utilizes and updates cache if `Acl` is locked.
    /// 
    /// # Precedence
    /// 
    /// Rules are searched depth first. The lineage of the resource and rule is retrieved.
    /// Resources are iterated in the outer for-loop, rules in the inner for-loop. In this inner
    /// loop privileges are queried with the specific name or the wildcard placeholder. If no rule
    /// is found the catch-all rule ist returned.
    pub fn get_rule(&self, role: Role, resource: Resource, privilege: Privilege) -> Rule {
        trace!("getting rule for {:?} on {:?} to {:?}", role, resource, privilege);
        // try direct query first
        if let Some(rule) = self.rules.get(&Query{resource, role, privilege}) {
            trace!("    matching direct query");
            return *rule;
        } // if

        // omit if equal to Query::ALL
        if resource.is_some() || role.is_some() || privilege.is_some() {
            // if this is locked try utilzing cache
            if let Some(cache) = &self.lock {
                let cache = cache.borrow(); 
                let rule  = cache.get(&Query{resource, role, privilege});

                if let Some(rule) = rule {
                    trace!("    cache hit");
                    return *rule;
                } // if
            } // if
            if let Some(rule) = self.query_precedence(role, resource, privilege) {
                trace!("    matched query");
                // if this is locked add this rule to the cache.
                if let Some(cache) = &self.lock {
                    trace!("    caching rule");
                    cache.borrow_mut().insert(Query{resource, role, privilege}, *rule);
                } // if
                return *rule;
            } // if let
        } // if

        // no specific rule defined, return rule for Query::ALL, this is always defined
        trace!("    matching catch-all");
        *self.rules.index(&Query::ALL)
    } // get_rule

    /// Some(...) is a specific definition and None is a wildcard. All roles, resources or
    /// privileges which are not None must be predefined.
    pub fn set_rule(&mut self, role: Role, resource: Resource, privilege: Privilege, access: Access) -> Result<(), Error> {
        trace!("setting rule for {:?} on {:?} with {:?} privilege", role, resource, privilege);

        // if this is locked, no new rules
        if self.lock.is_some() {
            return Err(Error::Locked);
        } // if

        // ensure that resource is defined
        if let Some(name) = resource {
            if !self.resources.contains_key(name) {
                return Err(Error::MissingResource(String::from(name)));
            } // if
        } // if

        // ensure that role is defined
        if let Some(name) = role {
            if !self.roles.contains_key(name) {
                return Err(Error::MissingRole(String::from(name)));
            } // if
        } // if

        let query = Query{resource, role, privilege};

        if query != Query::ALL {
            self.rules.insert(query, Rule{acc: access});
        } // if
        Ok(())
    } // set_rule

} // impl Acl

impl fmt::Debug for Acl {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        self.rules.fmt(f)
    } // fmt

} // impl fmt::Debug for Acl


// Error //////////////////////////////////////////////////////////////////////////////////////////


#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    DuplicateRole(String),
    MissingRole(String),
    MissingParent(String),
    DuplicateResource(String),
    MissingResource(String),
    Locked,
} // enum Error

impl fmt::Display for Error {

    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Error::DuplicateRole(s) =>
                write!(f, "Duplicate role: {}", s),
            Error::MissingRole(s) =>
                write!(f, "Missing role: {}", s),
            Error::MissingParent(s) =>
                write!(f, "Missing parent role: {}", s),
            Error::DuplicateResource(s) =>
                write!(f, "Duplicate resource: {}", s),
            Error::MissingResource(s) =>
                write!(f, "Missing resource: {}", s),
            Error::Locked =>
                write!(f, "acl is locked, no new rules may be defined"),
        } // match
    } // fmt

} // impl fmt::Display for Error


// Tests //////////////////////////////////////////////////////////////////////////////////////////


#[cfg(test)]
mod tests {

    use super::*;
    use test_env_log::test;

    fn setup_acl() -> Acl {
        let mut acl = Acl::new();

        assert!(acl.add_role("guest", vec![]).is_ok());
        assert!(acl.add_role("staff", vec!["guest"]).is_ok());
        assert!(acl.add_role("editor", vec!["staff"]).is_ok());
        assert!(acl.add_role("admin", vec![]).is_ok());

        // guest may only view content
        assert!(acl.allow(Some("guest"), None, Some("view")).is_ok());

        // staff inherits view privilege from guest, but also needs additional privileges
        assert!(acl.allow(Some("staff"), None, Some("edit")).is_ok());
        assert!(acl.allow(Some("staff"), None, Some("submit")).is_ok());
        assert!(acl.allow(Some("staff"), None, Some("revise")).is_ok());

        // editor inherits view, edit, submit, and revise privileges from staff, but also needs
        // additional privileges
        assert!(acl.allow(Some("editor"), None, Some("publish")).is_ok());
        assert!(acl.allow(Some("editor"), None, Some("archive")).is_ok());
        assert!(acl.allow(Some("editor"), None, Some("delete")).is_ok());

        // admin inherits nothing, but is allowed all privileges
        assert!(acl.allow(Some("admin"), None, None).is_ok());

        acl
    } // setup_acl

    fn extend_acl(acl: &mut Acl) {
        assert!(acl.add_role("marketing", vec!["staff"]).is_ok());

        assert!(acl.add_resource("newsletter", None).is_ok());
        assert!(acl.add_resource("news", None).is_ok());
        assert!(acl.add_resource("latest", Some("news")).is_ok());
        assert!(acl.add_resource("anouncement", Some("news")).is_ok());

        // marketing must be able to publish and archive newsletters and the latest news
        assert!(acl.allow(Some("marketing"), Some("newsletter"), Some("publish")).is_ok());
        assert!(acl.allow(Some("marketing"), Some("newsletter"), Some("archive")).is_ok());
        assert!(acl.allow(Some("marketing"), Some("latest"), Some("publish")).is_ok());
        assert!(acl.allow(Some("marketing"), Some("latest"), Some("archive")).is_ok());

        // staff (and marketing, by inheritance), are denied permission to revise the latest news
        assert!(acl.deny(Some("staff"), Some("latest"), Some("revise")).is_ok());
        
        // everyone (including admins) are denied permission to archive news announcements
        assert!(acl.deny(None, Some("anouncement"), Some("archive")).is_ok());
    } // extend_acl

    #[test]
    fn roles() {
        let mut acl = Acl::new();

        assert!(acl.add_role("guest", vec![]).is_ok());
        assert!(acl.add_role("staff", vec!["guest"]).is_ok());
        assert!(acl.has_role("guest"));
        assert!(acl.has_role("staff"));

        let res = acl.add_role("guest", vec![]);

        assert!(res.is_err());
        assert_eq!(Error::DuplicateRole(String::from("guest")), res.unwrap_err());

        let res = acl.get_role_parents("admin");

        assert!(res.is_err());
        assert_eq!(Error::MissingRole(String::from("admin")), res.unwrap_err());

        let res = acl.get_role_parents("guest");

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Vec::<&'static str>::new());

        let res = acl.get_role_parents("staff");

        assert!(res.is_ok());
        assert_eq!(vec!["guest"], res.unwrap());
    } // roles

    #[test]
    fn resources() {
        let mut acl = Acl::new();

        assert!(acl.add_resource("blog post", None).is_ok());

        let res = acl.add_resource("blog post", None);

        assert!(res.is_err());
        assert_eq!(Error::DuplicateResource(String::from("blog post")), res.unwrap_err());
    } // resources

    #[test]
    fn defaults() {
        let acl = Acl::new();

        assert!(!acl.is_allowed(None, None, None));
        assert!(acl.is_denied(None, None, None));
    } // defaults

    #[test]
    fn lineage() {
        let mut acl = Acl::new();

        assert!(acl.add_role("guest", vec![]).is_ok());
        assert!(acl.add_role("staff", vec!["guest"]).is_ok());
        assert!(acl.add_role("editor", vec!["staff"]).is_ok());
        assert!(acl.add_role("publisher", vec!["editor"]).is_ok());
        assert!(acl.add_role("supervisor", vec!["editor"]).is_ok());

        assert_eq!(acl.get_role_lineage("admin"), Vec::<&str>::new());
        assert_eq!(acl.get_role_lineage("guest"), vec!["guest"]);
        assert_eq!(acl.get_role_lineage("staff"), vec!["staff", "guest"]);
        assert_eq!(acl.get_role_lineage("editor"), vec!["editor", "staff", "guest"]);
        assert_eq!(acl.get_role_lineage("publisher"), vec!["publisher", "editor", "staff", "guest"]);
        assert_eq!(acl.get_role_lineage("supervisor"), vec!["supervisor", "editor", "staff", "guest"]);
    } // lineage

    #[test]
    fn ancestor() {
        let mut acl = Acl::new();

        assert!(acl.add_role("guest", vec![]).is_ok());
        assert!(acl.add_role("staff", vec!["guest"]).is_ok());
        assert!(acl.add_role("editor", vec!["staff"]).is_ok());
        assert!(acl.add_role("publisher", vec!["editor"]).is_ok());
        assert!(acl.add_role("supervisor", vec!["editor"]).is_ok());

        assert_eq!(acl.get_role_ancestors("admin"), Vec::<&str>::new());
        assert_eq!(acl.get_role_ancestors("guest"), Vec::<&str>::new());
        assert_eq!(acl.get_role_ancestors("staff"), vec!["guest"]);
        assert_eq!(acl.get_role_ancestors("editor"), vec!["staff", "guest"]);
        assert_eq!(acl.get_role_ancestors("publisher"), vec!["editor", "staff", "guest"]);
        assert_eq!(acl.get_role_ancestors("supervisor"), vec!["editor", "staff", "guest"]);
    } // ancestor

    #[test]
    fn rules() {
        let mut acl = setup_acl();

        // allowed
        assert!( acl.is_allowed(Some("guest"), None, Some("view")));
        assert!(!acl.is_denied (Some("guest"), None, Some("view")));

        // denied
        assert!(!acl.is_allowed(Some("staff"), None, Some("publish")));
        assert!( acl.is_denied (Some("staff"), None, Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("staff"), None, Some("revise")));
        assert!(!acl.is_denied (Some("staff"), None, Some("revise")));

        // allowed because of inheritance from guest
        assert!( acl.is_allowed(Some("editor"), None, Some("view")));
        assert!(!acl.is_denied (Some("editor"), None, Some("view")));

        // denied because no allow rule for 'update'
        assert!(!acl.is_allowed(Some("editor"), None, Some("update")));
        assert!( acl.is_denied (Some("editor"), None, Some("update")));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, Some("view")));
        assert!(!acl.is_denied (Some("admin"), None, Some("view")));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, None));
        assert!(!acl.is_denied (Some("admin"), None, None));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, Some("update")));
        assert!(!acl.is_denied (Some("admin"), None, Some("update")));

        // precise access controls ////////////////////////////////////////////////////////////////

        extend_acl(&mut acl);

        // denied
        assert!(!acl.is_allowed(Some("staff"), Some("newsletter"), Some("publish")));
        assert!( acl.is_denied (Some("staff"), Some("newsletter"), Some("publish")));
        
        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("newsletter"), Some("publish")));
        assert!(!acl.is_denied (Some("marketing"), Some("newsletter"), Some("publish")));

        // denied
        assert!(!acl.is_allowed(Some("staff"), Some("latest"), Some("publish")));
        assert!( acl.is_denied (Some("staff"), Some("latest"), Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("publish")));
        assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("archive")));
        assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("archive")));

        // denied
        assert!(!acl.is_allowed(Some("marketing"), Some("latest"), Some("revise")));
        assert!( acl.is_denied (Some("marketing"), Some("latest"), Some("revise")));

        // denied
        assert!(!acl.is_allowed(Some("editor"), Some("anouncement"), Some("archive")));
        assert!( acl.is_denied (Some("editor"), Some("anouncement"), Some("archive")));

        // denied
        assert!(!acl.is_allowed(Some("admin"), Some("anouncement"), Some("archive")));
        assert!( acl.is_denied (Some("admin"), Some("anouncement"), Some("archive")));
    } // rules

    #[test]
    fn cache() {
        let mut acl = setup_acl();

        extend_acl(&mut acl);
        acl.lock();

        // allowed
        assert!( acl.is_allowed(Some("guest"), None, Some("view")));
        assert!(!acl.is_denied (Some("guest"), None, Some("view")));

        // denied
        assert!(!acl.is_allowed(Some("staff"), None, Some("publish")));
        assert!( acl.is_denied (Some("staff"), None, Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("staff"), None, Some("revise")));
        assert!(!acl.is_denied (Some("staff"), None, Some("revise")));

        // allowed because of inheritance from guest
        assert!( acl.is_allowed(Some("editor"), None, Some("view")));
        assert!(!acl.is_denied (Some("editor"), None, Some("view")));

        // denied because no allow rule for 'update'
        assert!(!acl.is_allowed(Some("editor"), None, Some("update")));
        assert!( acl.is_denied (Some("editor"), None, Some("update")));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, Some("view")));
        assert!(!acl.is_denied (Some("admin"), None, Some("view")));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, None));
        assert!(!acl.is_denied (Some("admin"), None, None));

        // allowed because admin is allowed all privileges
        assert!( acl.is_allowed(Some("admin"), None, Some("update")));
        assert!(!acl.is_denied (Some("admin"), None, Some("update")));

        // precise access controls ////////////////////////////////////////////////////////////////

        // denied
        assert!(!acl.is_allowed(Some("staff"), Some("newsletter"), Some("publish")));
        assert!( acl.is_denied (Some("staff"), Some("newsletter"), Some("publish")));
        
        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("newsletter"), Some("publish")));
        assert!(!acl.is_denied (Some("marketing"), Some("newsletter"), Some("publish")));

        // denied
        assert!(!acl.is_allowed(Some("staff"), Some("latest"), Some("publish")));
        assert!( acl.is_denied (Some("staff"), Some("latest"), Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("publish")));
        assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("publish")));

        // allowed
        assert!( acl.is_allowed(Some("marketing"), Some("latest"), Some("archive")));
        assert!(!acl.is_denied (Some("marketing"), Some("latest"), Some("archive")));

        // denied
        assert!(!acl.is_allowed(Some("marketing"), Some("latest"), Some("revise")));
        assert!( acl.is_denied (Some("marketing"), Some("latest"), Some("revise")));

        // denied
        assert!(!acl.is_allowed(Some("editor"), Some("anouncement"), Some("archive")));
        assert!( acl.is_denied (Some("editor"), Some("anouncement"), Some("archive")));

        // denied
        assert!(!acl.is_allowed(Some("admin"), Some("anouncement"), Some("archive")));
        assert!( acl.is_denied (Some("admin"), Some("anouncement"), Some("archive")));
    } // rules

} // mod tests