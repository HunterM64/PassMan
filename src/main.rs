/*
    TODO:
        make it have Create, Read, Update, Delete functionality

        CREATE: - generate
            possibly copy password to clipboard
        UPDATE: - update
            give name of website you want to regenerate a password for
            update password in db
        DELETE: - delete
            give name of website to delete record of in db
 */

use structopt::StructOpt;
use whoami;
use sqlite::{self, State, Connection};
use rpassword;
// use std::{hash::{Hash, Hasher}, collections::hash_map::DefaultHasher};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::{thread_rng};
use rand::seq::IteratorRandom;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};


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
    let mut db_password = String::new();

    // unoptimized as shit!
    while let Ok(State::Row) = stmt.next() {
        let name = stmt.read::<String, _>("name").unwrap();
        db_password = stmt.read::<String, _>("password").unwrap();

        if name.eq(&username) {
            existing = true;
            break;
        }
    }

    drop(stmt);

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
        
        let parsed_db_password = PasswordHash::new(&db_password).unwrap();


        if Argon2::default().verify_password(line.as_bytes(), &parsed_db_password).is_ok() { // check hash not actual plaintext
            // If so, execute command
            match_subcommand(username, db_password);
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
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();

            let line_hash = argon2.hash_password(line.as_bytes(), &salt).unwrap().to_string();
            println!("{}", line_hash);

            // insert into database
            let query = format!("INSERT INTO users VALUES ('{username}', '{line_hash}');"); // hash this lmao
            conn_users.execute(query).unwrap();

            println!("User successfully created!\nPlease rerun your previous command to start using PassMan.");
        } else {
            println!("Passwords do not match!");
        }
    }

    drop(conn_users);

}

/// executes the proper subcommand based on the command line arguments given
fn match_subcommand(username: String, password: String) {
    let opt = PassMan::from_args();
    match opt {
        PassMan::Generate { length, website } => {
            generate(length, website, username, password);
        },

        PassMan::List { website } => {
            list(website, username, password);
        },

        PassMan::Update { website } => {
            update(website);
        },

        PassMan::Delete { website } => {
            delete(website);
        }
    }
}

/// Returns a password of length given
fn generate(length: u32, website: Option<String>, username: String, password: String) {

    if length < 4 {
        println!("I need at least 4 as the length.");
        return;
    }
    
    if length < 8 {
        println!("I would heavily consider making your password length at least 8 characters.");
    }

    let generated_password = generate_password(length);

    println!("Password is: {generated_password}");
    
    match website {
        None => {},
        Some(name) => {
            // save to database
            println!("Saving record for {name}...");
            
            // encrypt password first
            let mc = new_magic_crypt!(password, 256);
            let encrypted_password = mc.encrypt_str_to_base64(generated_password);

            // connect to database
            let conn = sqlite::open("test.db").unwrap();

            // insert password into db
            let query = format!("INSERT INTO passwords VALUES ('{username}', '{name}', '{encrypted_password}');");
            conn.execute(query).unwrap();

            println!("Password saved successfuly.");
            
            drop(conn);
        }
    }
}

fn list(website: Option<String>, username: String, password: String) {
    match website {
        None => {
            println!("Here are all the websites with saved passwords:");

            // db stuff
            let conn = sqlite::open("test.db").unwrap();
            let query = format!("SELECT website_name FROM passwords WHERE username = '{username}'");
            let mut stmt = conn.prepare(query).unwrap();

            // list all the websites
            while let Ok(State::Row) = stmt.next() {
                println!("{}", stmt.read::<String, _>("website_name").unwrap());
            }

            drop(stmt);
            drop(conn);
        },
        Some(website_name) => {
            
            // db stuff
            let conn = sqlite::open("test.db").unwrap();
            let query = format!("SELECT password from passwords WHERE website_name = '{website_name}'");
            let mut stmt = conn.prepare(query).unwrap();

            while let Ok(State::Row) = stmt.next() {
                let encrypted_password = stmt.read::<String, _>("password").unwrap();
                let mc = new_magic_crypt!(password.clone(), 256);
                let decrypted_password = mc.decrypt_base64_to_string(&encrypted_password).unwrap();

                println!("Here is the password of {website_name}: {decrypted_password}");
            }

            drop(stmt);
            drop(conn);
        } 
    }
}

fn update(website: String) {
    println!("update {website}");
}

fn delete(website: String) {
    println!("delete {website}");
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

/// Returns a randomly generated password that is <length> characters long
fn generate_password(length: u32) -> String {
    
    let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_=+"; //characters that passwords can use
    let mut rng = thread_rng(); 
    let mut generated_password = String::from("");

    for _ in 0..length {
        // println!("{}", characters.chars().choose(&mut rng).unwrap());
        generated_password.push(characters.chars().choose(&mut rng).unwrap());
    }

    // verify password - i tried regex but i dont want to talk about it
    while !(validate_password(generated_password.clone())) {
        generated_password = generate_password(length);
    }

    return generated_password;
}

/// Returns true if password is valid, false otherwise.
fn validate_password(password: String) -> bool {

    let specialchars = "!@#$%^&*()-_=+";

    let mut valid: bool = true;

    if !(password.chars().any(|c| matches!(c, 'a'..='z'))) {
        valid = false;
    } else if !(password.chars().any(|c| matches!(c, 'A'..='Z'))) {
        valid = false;
    } else if !(password.chars().any(|c| matches!(c, '0'..='9'))) {
        valid = false;
    } else if !(password.chars().any(|c| specialchars.contains(c))) {
        valid = false;
    }

    return valid;
}

// fn calc_hash<T: Hash>(t: &T) -> u64 {
//     let mut s = DefaultHasher::new();
//     t.hash(&mut s);
//     return s.finish();
// }
