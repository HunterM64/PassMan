/*
    TODO:
        make it have Create, Read, Update, Delete functionality

        CREATE: - generate
            generate random passwords of given length
            save generated passwords under passwords table (username, website_name, password)
            possibly copy password to clipboard
        READ: - list
            List all websites that have passwords saved if given no args, list password of entered website if given
        UPDATE: - update
            give name of website you want to regenerate a password for
            update password in db
        DELETE: - delete
            give name of website to delete record of in db

        encryption for all saved passwords
 */

use structopt::StructOpt;
use whoami;
use sqlite::{self, State, Connection};
use rpassword;
use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};

#[derive(Debug, StructOpt)]
#[structopt(name = "passman", about = "command line password manager")]

enum PassMan { // struct for command line arguments
    #[structopt(name = "generate")] // generates passwords
    /// Generates passwords
    Generate {
        /// Length of generated password
        length: u32,

        #[structopt(
            short = "s",
            long = "store",
        )]
        /// Optionally save record of generated password with <website>
        website: Option<String>, 
    },

    #[structopt(name = "list")]
    /// Lists records of all websites with saved passwords
    List {
        #[structopt(
            short = "w",
            long = "website",
        )]
        /// Optionally retrieve password of <website>
        website: Option<String>,
    },

    #[structopt(name = "update")]
    /// Updates password of given website
    Update {
        /// Website to generate new password for
        website: String,
    },

    #[structopt(name = "delete")]
    /// Deletes record of given website
    Delete {
        /// Website to delete records of
        website: String,
    },

}
fn main() {

    // set up db (set up connection, create user table if it doesn't exist)
    let conn_users = setup_user_db();

    // see if user is in database already
    let mut existing = false;

    // get username of computer
    let username = whoami::username();
    //println!("username: {username}");
    
    // get all users in database
    let query = "SELECT name, password FROM users";
    let mut stmt = conn_users.prepare(query).unwrap();

    // might as well get password while we're at it
    let mut password = String::new();

    // unoptimized as shit!
    while let Ok(State::Row) = stmt.next() {
        let name = stmt.read::<String, _>("name").unwrap();
        password = stmt.read::<String, _>("password").unwrap();

        if name.eq(&username) {
            existing = true;
            break;
        }
    }

    if existing {
        // Need to authenticate with password

        // println!("Enter password: ");

        // // get password from user input
        // let mut line = String::new();
        // std::io::stdin().read_line(&mut line).unwrap();
        // line.pop();

        // get password without displaying it in the terminal
        let line = rpassword::prompt_password("Enter password: ").unwrap();

        // check that password entered matches password in database
        let line_hash = (calc_hash(&line)).to_string();
        if password.eq(&line_hash) { // check hash not actual plaintext
            // If so, execute command
            match_subcommand();
        } else {
            // Reject
            println!("Incorrect Password!");
        }
    } else {
        // User needs to make a password

        println!("It looks like this is your first time using PassMan.\nTo start using PassMan, you will first need to create a password (Ironic, I know).");
        // println!("Enter password: ");

        // // get password from user input
        // let mut line = String::new();
        // std::io::stdin().read_line(&mut line).unwrap();
        // line.pop();
        let line = rpassword::prompt_password("Enter password: ").unwrap();
        let line_verification = rpassword::prompt_password("Enter password again to confirm: ").unwrap();

        // make sure both passwords match
        if line_verification.eq(&line) {
            // calc hash
            let line_hash = (calc_hash(&line)).to_string();

            // insert into database
            let query = format!("INSERT INTO users VALUES ('{username}', '{line_hash}');"); // hash this lmao
            conn_users.execute(query).unwrap();

            println!("User successfully created!\nPlease rerun your previous command to start using PassMan.");
        } else {
            println!("Passwords do not match!");
        }
    }
}

/// executes the proper subcommand based on the command line arguments given
fn match_subcommand() {
    let opt = PassMan::from_args();
    match opt {
        PassMan::Generate { length, website } => {
            generate(length, website);
        },

        PassMan::List { website } => {
            list(website);
        },

        PassMan::Update { website } => {
            println!("update {website}");
        },

        PassMan::Delete { website } => {
            println!("delete {website}");
        }
    }
}

/// Returns a password of length given
fn generate(length: u32, website: Option<String>) {
    println!("{}", length);
    match website {
        None => {},
        Some(name) => {
            println!("you entered {name}");
        }
    }
}

fn list(website: Option<String>) {
    match website {
        None => {
            println!("Here are all the websites with saved passwords:")
        }, // list all websites with saved passwords
        Some(website_name) => {
            println!("Here is the password of {website_name}:");
        } // list password of website
    }
}

/// Setup database for PassMan if it doesn't exist already
fn setup_user_db() -> Connection {
    let conn = sqlite::open("test.db").unwrap();   
    
    // create users table if not exists
    let mut query = "CREATE TABLE IF NOT EXISTS users (name TEXT, password TEXT)";
    conn.execute(query).unwrap();

    // create passwords table if not exists
    query = "CREATE TABLE IF NOT EXISTS passwords (username TEXT, website_name TEXT, password TEXT)";
    conn.execute(query).unwrap();

    // return connnection to database
    return conn;
}

fn calc_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    return s.finish();
}
