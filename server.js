import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import mysql from "mysql2/promise";
import { promisify } from "util";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env"), override: true });

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));
app.use(express.static("."));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if(req.method === "OPTIONS"){
    return res.sendStatus(204);
  }
  next();
});

const AUTH_EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUTH_MIN_PASSWORD_LENGTH = 8;
const AUTH_MIN_NAME_LENGTH = 2;
const AUTH_MAX_NAME_LENGTH = 80;
const scryptAsync = promisify(crypto.scrypt);
const generatedImageCache = new Map();
const MAX_IMAGE_CACHE_SIZE = 100;
const THEMEALDB_BASE_URL = "https://www.themealdb.com/api/json/v1/1";
const THEMEALDB_RESULT_LIMIT = 6;
const THEMEALDB_DETAIL_LOOKUP_LIMIT = 10;
const THEMEALDB_AREA_ALIASES = {
  usa: "american",
  us: "american",
  "united states": "american",
  uk: "british",
  "united kingdom": "british",
  england: "british",
  scotland: "british",
  wales: "british",
  china: "chinese",
  croatia: "croatian",
  netherlands: "dutch",
  egypt: "egyptian",
  france: "french",
  greece: "greek",
  india: "indian",
  ireland: "irish",
  italy: "italian",
  jamaica: "jamaican",
  japan: "japanese",
  kenya: "kenyan",
  malaysia: "malaysian",
  mexico: "mexican",
  morocco: "moroccan",
  poland: "polish",
  portugal: "portuguese",
  russia: "russian",
  spain: "spanish",
  thailand: "thai",
  tunisia: "tunisian",
  turkey: "turkish",
  vietnam: "vietnamese"
};
const REQUEST_TIMEOUT_MS = (() => {
  const parsed = Number.parseInt(String(process.env.REQUEST_TIMEOUT_MS || "15000"), 10);
  return Number.isNaN(parsed) ? 15000 : parsed;
})();
const MAX_RETRIES = 3;
const INITIAL_RETRY_DELAY_MS = 500;

function getAuthConfig(){
  const configuredPort = Number.parseInt(String(process.env.DB_PORT || "3306"), 10);
  return {
    host: String(process.env.DB_HOST || "127.0.0.1"),
    port: Number.isNaN(configuredPort) ? 3306 : configuredPort,
    user: String(process.env.DB_USER || "root"),
    password: String(process.env.DB_PASSWORD || ""),
    database: String(process.env.DB_NAME || "cookbot")
  };
}

function validateDbName(value){
  const dbName = String(value || "").trim();
  if(!dbName || !/^[a-zA-Z0-9_]+$/.test(dbName)){
    throw new Error("DB_NAME must contain only letters, numbers, and underscores.");
  }
  return dbName;
}

function normalizeEmail(value){
  return String(value || "").trim().toLowerCase();
}

function normalizeFullName(value){
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, AUTH_MAX_NAME_LENGTH);
}

function isValidEmail(value){
  return AUTH_EMAIL_REGEX.test(value);
}

function isValidPassword(value){
  return String(value || "").length >= AUTH_MIN_PASSWORD_LENGTH;
}

function isValidFullName(value){
  return normalizeFullName(value).length >= AUTH_MIN_NAME_LENGTH;
}

async function hashPassword(password){
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt, 64);
  return `${salt}:${Buffer.from(derivedKey).toString("hex")}`;
}

async function verifyPassword(password, storedHash){
  const [salt, keyHex] = String(storedHash || "").split(":");
  if(!salt || !keyHex){
    return false;
  }

  const candidate = Buffer.from(await scryptAsync(password, salt, 64));
  const stored = Buffer.from(keyHex, "hex");

  if(candidate.length !== stored.length){
    return false;
  }

  return crypto.timingSafeEqual(candidate, stored);
}

async function initAuthPool(){
  const config = getAuthConfig();
  const dbName = validateDbName(config.database);

  const bootstrap = await mysql.createConnection({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password
  });

  try{
    await bootstrap.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  }finally{
    await bootstrap.end();
  }

  const pool = mysql.createPool({
    host: config.host,
    port: config.port,
    user: config.user,
    password: config.password,
    database: dbName,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(191) NOT NULL UNIQUE,
      full_name VARCHAR(120) NOT NULL DEFAULT '',
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const [userFullNameColumn] = await pool.query("SHOW COLUMNS FROM users LIKE 'full_name'");
  if(!Array.isArray(userFullNameColumn) || !userFullNameColumn.length){
    await pool.query("ALTER TABLE users ADD COLUMN full_name VARCHAR(120) NOT NULL DEFAULT '' AFTER email");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_activity (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      email VARCHAR(191) NOT NULL,
      action_type VARCHAR(32) NOT NULL,
      success TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_auth_activity_email (email),
      INDEX idx_auth_activity_created_at (created_at),
      CONSTRAINT fk_auth_activity_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL
    )
  `);

  return pool;
}

const authPoolPromise = initAuthPool();
authPoolPromise.catch((err) => {
  const safeMessage = redactSecrets(err?.message) || "Auth database init failed.";
  console.error("Auth DB init error:", safeMessage);
});

async function getAuthPool(){
  return authPoolPromise;
}

async function getUserByEmail(pool, email){
  const [rows] = await pool.query(
    "SELECT id, email, full_name, password_hash FROM users WHERE email = ? LIMIT 1",
    [email]
  );

  return Array.isArray(rows) && rows.length ? rows[0] : null;
}

async function recordAuthActivity(pool, { userId = null, email = "", actionType = "", success = false } = {}){
  const normalizedEmail = normalizeEmail(email);
  const normalizedAction = String(actionType || "").trim().toLowerCase().slice(0, 32);

  if(!normalizedEmail || !normalizedAction){
    return;
  }

  await pool.query(
    "INSERT INTO auth_activity (user_id, email, action_type, success) VALUES (?, ?, ?, ?)",
    [userId, normalizedEmail, normalizedAction, success ? 1 : 0]
  );
}

function mapAuthServiceError(err){
  const code = String(err?.code || "").toUpperCase();
  if(code === "ECONNREFUSED"){
    return {
      status: 503,
      error: "Auth database is unreachable. Start MySQL and verify DB_HOST/DB_PORT."
    };
  }
  if(code === "ENOTFOUND"){
    return {
      status: 503,
      error: "Auth database host not found. Check DB_HOST in .env."
    };
  }
  if(code === "ER_ACCESS_DENIED_ERROR"){
    return {
      status: 503,
      error: "Auth database credentials are invalid. Check DB_USER/DB_PASSWORD in .env."
    };
  }
  if(code === "ER_BAD_DB_ERROR"){
    return {
      status: 503,
      error: "Auth database is not available. Check DB_NAME in .env."
    };
  }
  return null;
}

function redactSecrets(value){
  let safe = String(value || "");
  const secrets = [process.env.DB_PASSWORD].filter(Boolean);

  secrets.forEach((secret) => {
    safe = safe.split(secret).join("[REDACTED]");
  });

  return safe;
}

function stripMarkdownFences(text){
  return String(text || "").replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
}

function cacheGeneratedImage(key, value){
  if(!key || !value) return;
  if(generatedImageCache.size >= MAX_IMAGE_CACHE_SIZE){
    const oldestKey = generatedImageCache.keys().next().value;
    generatedImageCache.delete(oldestKey);
  }
  generatedImageCache.set(key, value);
}

function normalizeRecipeLookupTerm(value){
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 100);
}

function getMealDbImageFromMeals(meals, recipeName){
  if(!Array.isArray(meals) || !meals.length){
    return "";
  }

  const normalizedTarget = normalizeRecipeLookupTerm(recipeName).toLowerCase();
  const exact = meals.find((meal) => String(meal?.strMeal || "").trim().toLowerCase() === normalizedTarget);
  if(exact?.strMealThumb){
    return String(exact.strMealThumb).trim();
  }

  const partial = meals.find((meal) => {
    const name = String(meal?.strMeal || "").trim().toLowerCase();
    return name.includes(normalizedTarget) || normalizedTarget.includes(name);
  });
  if(partial?.strMealThumb){
    return String(partial.strMealThumb).trim();
  }

  const firstWithImage = meals.find((meal) => String(meal?.strMealThumb || "").trim());
  return String(firstWithImage?.strMealThumb || "").trim();
}

function normalizeIngredientSearchTerm(value){
  return String(value || "")
    .toLowerCase()
    .replace(/[^\w\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 40);
}

function extractIngredientQueries(message){
  const stopWords = new Set([
    "a", "an", "and", "can", "cook", "dish", "dishes", "find", "for", "from", "give",
    "got", "have", "i", "idea", "ideas", "ingredient", "ingredients", "make", "meal",
    "me", "meals", "need", "of", "please", "recipe", "recipes", "show", "some",
    "something", "suggest", "the", "using", "want", "with", "you"
  ]);
  const normalized = String(message || "")
    .toLowerCase()
    .replace(/[\r\n]+/g, ",")
    .replace(/[+/;&]/g, ",")
    .replace(/\b(and|with|using|plus)\b/g, ",");

  const cleaned = normalized
    .split(",")
    .map((part) => part
      .split(/\s+/)
      .map((token) => normalizeIngredientSearchTerm(token))
      .filter((token) => token && !stopWords.has(token))
      .join(" "))
    .map((part) => normalizeIngredientSearchTerm(part))
    .filter(Boolean);

  return Array.from(new Set(cleaned)).slice(0, 5);
}

function extractMealIngredients(meal){
  const ingredients = [];

  for(let index = 1; index <= 20; index += 1){
    const ingredient = String(meal?.[`strIngredient${index}`] || "").trim();
    const measure = String(meal?.[`strMeasure${index}`] || "").trim();
    if(!ingredient) continue;
    ingredients.push(measure ? `${measure} ${ingredient}`.trim() : ingredient);
  }

  return ingredients;
}

function normalizeOriginValue(value){
  return String(value || "")
    .toLowerCase()
    .replace(/[^\w\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function estimateMealMinutes(meal){
  const ingredientCount = extractMealIngredients(meal).length;
  const instructionLength = String(meal?.strInstructions || "").trim().length;
  const score = instructionLength + (ingredientCount * 35);

  if(score <= 520) return 20;
  if(score <= 920) return 35;
  return 50;
}

function estimateMealDifficulty(meal){
  const ingredientCount = extractMealIngredients(meal).length;
  const instructionLength = String(meal?.strInstructions || "").trim().length;
  const score = instructionLength + (ingredientCount * 40);

  if(score <= 560) return "Easy";
  if(score <= 980) return "Medium";
  return "Hard";
}

function buildMealTag(meal){
  const area = String(meal?.strArea || "").trim();
  const category = String(meal?.strCategory || "").trim();
  const parts = [
    area,
    category,
    `${estimateMealMinutes(meal)} min`,
    estimateMealDifficulty(meal)
  ].filter(Boolean);
  return parts.length ? parts.join(" | ") : "TheMealDB";
}

function buildMealDesc(meal){
  const ingredients = extractMealIngredients(meal);
  return ingredients.slice(0, 8).join(", ");
}

function getOriginPriority(meal, origin){
  const normalizedOrigin = normalizeOriginValue(origin);
  const mealOrigin = normalizeOriginValue(meal?.strArea);

  if(!normalizedOrigin){
    return 0;
  }

  const aliasOrigin = THEMEALDB_AREA_ALIASES[normalizedOrigin] || normalizedOrigin;
  return mealOrigin === aliasOrigin ? 2 : 0;
}

function scoreMealForDietaryPreference(meal, dietaryPreference){
  const preference = String(dietaryPreference || "").trim().toLowerCase();
  if(!preference){
    return 0;
  }

  const haystack = [
    String(meal?.strCategory || ""),
    String(meal?.strMeal || ""),
    ...extractMealIngredients(meal)
  ]
    .join(" ")
    .toLowerCase();

  const hasAny = (terms) => terms.some((term) => haystack.includes(term));
  const meatTerms = ["beef", "chicken", "pork", "lamb", "goat", "ham", "bacon", "turkey", "duck", "sausage", "anchovy", "fish", "salmon", "tuna", "shrimp", "prawn", "crab", "oyster", "mussel"];
  const animalTerms = [...meatTerms, "egg", "milk", "cream", "cheese", "butter", "yogurt", "honey"];
  const nutTerms = ["peanut", "almond", "cashew", "walnut", "pecan", "hazelnut", "pistachio"];
  const glutenTerms = ["flour", "bread", "pasta", "spaghetti", "noodle", "soy sauce", "wheat", "breadcrumb"];
  const carbTerms = ["rice", "pasta", "potato", "bread", "flour", "sugar", "bean", "lentil", "chickpea"];
  const proteinTerms = ["chicken", "beef", "egg", "tofu", "salmon", "tuna", "shrimp", "yogurt", "beans", "lentils"];

  if(preference === "vegetarian"){
    return hasAny(meatTerms) ? -100 : 3;
  }

  if(preference === "vegan"){
    return hasAny(animalTerms) ? -100 : 3;
  }

  if(preference === "nut-free"){
    return hasAny(nutTerms) ? -100 : 2;
  }

  if(preference === "gluten-free"){
    return hasAny(glutenTerms) ? -100 : 2;
  }

  if(preference === "keto"){
    return hasAny(carbTerms) ? -2 : 1;
  }

  if(preference === "high-protein"){
    return hasAny(proteinTerms) ? 2 : 0;
  }

  return 0;
}

function shouldApplyStrictDietaryFilter(dietaryPreference){
  const preference = String(dietaryPreference || "").trim().toLowerCase();
  return ["vegetarian", "vegan", "nut-free", "gluten-free"].includes(preference);
}

function buildMealDbReply(recipes, ingredients, origin, dietaryPreference){
  const count = Array.isArray(recipes) ? recipes.length : 0;
  const joinedIngredients = ingredients.join(", ");
  const segments = [];

  if(count){
    segments.push(`Found ${count} recipe${count === 1 ? "" : "s"} for ${joinedIngredients}.`);
  }else{
    segments.push(`No recipes found for ${joinedIngredients}.`);
  }

  if(origin){
    segments.push(`Country priority: ${origin}.`);
  }

  if(dietaryPreference){
    segments.push(`Diet filter: ${dietaryPreference} (best-effort).`);
  }

  return segments.join(" ");
}

async function searchRecipesByIngredients(message, origin = "", dietaryPreference = ""){
  const ingredients = extractIngredientQueries(message);
  if(!ingredients.length){
    throw new Error("Provide at least one ingredient to search recipes.");
  }

  const matches = new Map();

  const results = await Promise.allSettled(ingredients.map(async (ingredient) => {
    const meals = await fetchMealsByIngredient(ingredient);

    meals.forEach((meal) => {
      const idMeal = String(meal?.idMeal || "").trim();
      if(!idMeal) return;

      const existing = matches.get(idMeal) || {
        idMeal,
        strMeal: String(meal?.strMeal || "").trim(),
        strMealThumb: String(meal?.strMealThumb || "").trim(),
        matchedIngredients: new Set()
      };

      existing.matchedIngredients.add(ingredient);
      matches.set(idMeal, existing);
    });
  }));

  // Check if all ingredient lookups failed
  const allFailed = results.every(result => result.status === "rejected");
  if(allFailed){
    const errors = results
      .filter(r => r.status === "rejected")
      .map(r => String(r.reason?.message || "Unknown error"))
      .slice(0, 2);
    throw new Error(`Failed to search ingredients: ${errors.join("; ")}`);
  }

  if(!matches.size){
    return {
      ingredients,
      reply: buildMealDbReply([], ingredients, origin, dietaryPreference),
      recipes: []
    };
  }

  const candidateIds = Array.from(matches.values())
    .sort((left, right) => {
      const byMatches = right.matchedIngredients.size - left.matchedIngredients.size;
      if(byMatches !== 0){
        return byMatches;
      }

      return left.strMeal.localeCompare(right.strMeal);
    })
    .slice(0, THEMEALDB_DETAIL_LOOKUP_LIMIT)
    .map((item) => item.idMeal);

  const detailResults = await Promise.allSettled(candidateIds.map(async (idMeal) => {
    return await fetchMealById(idMeal);
  }));

  const detailedMeals = detailResults
    .filter(result => result.status === "fulfilled")
    .map(result => result.value)
    .filter(Boolean);

  let rankedRecipes = detailedMeals
    .map((meal) => {
      const match = matches.get(String(meal?.idMeal || "").trim());
      return {
        meal,
        matchCount: match?.matchedIngredients?.size || 0,
        matchedIngredients: Array.from(match?.matchedIngredients || []),
        dietaryScore: scoreMealForDietaryPreference(meal, dietaryPreference),
        originPriority: getOriginPriority(meal, origin)
      };
    });

  if(shouldApplyStrictDietaryFilter(dietaryPreference)){
    rankedRecipes = rankedRecipes.filter((item) => item.dietaryScore >= 0);
  }

  const recipes = rankedRecipes
    .sort((left, right) => {
      const byMatches = right.matchCount - left.matchCount;
      if(byMatches !== 0){
        return byMatches;
      }

      const byOrigin = right.originPriority - left.originPriority;
      if(byOrigin !== 0){
        return byOrigin;
      }

      const byDietary = right.dietaryScore - left.dietaryScore;
      if(byDietary !== 0){
        return byDietary;
      }

      return String(left.meal?.strMeal || "").localeCompare(String(right.meal?.strMeal || ""));
    })
    .slice(0, THEMEALDB_RESULT_LIMIT)
    .map(({ meal, matchedIngredients }) => ({
      id: String(meal?.idMeal || "").trim(),
      name: String(meal?.strMeal || "").trim() || "Recipe",
      desc: buildMealDesc(meal),
      tag: buildMealTag(meal),
      image: String(meal?.strMealThumb || "").trim(),
      imageAlt: String(meal?.strMeal || "").trim() || "Recipe",
      instructions: String(meal?.strInstructions || "").trim(),
      ingredients: extractMealIngredients(meal),
      area: String(meal?.strArea || "").trim(),
      category: String(meal?.strCategory || "").trim(),
      youtube: String(meal?.strYoutube || "").trim(),
      matchedIngredients
    }));

  return {
    ingredients,
    reply: buildMealDbReply(recipes, ingredients, origin, dietaryPreference),
    recipes
  };
}

async function fetchJsonWithTimeout(url){
  let lastError;
  
  for(let attempt = 0; attempt <= MAX_RETRIES; attempt += 1){
    try{
      const response = await fetch(url, {
        method: "GET",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
      });

      if(!response.ok){
        const body = await response.text();
        const detail = stripMarkdownFences(body).slice(0, 240);
        const error = new Error(`Request failed with status ${response.status}${detail ? `: ${detail}` : ""}`);
        error.statusCode = response.status;
        error.isRetryable = response.status >= 500 || response.status === 429;
        throw error;
      }

      return await response.json();
    }catch(err){
      lastError = err;
      const message = String(err?.message || "Unknown request failure").toLowerCase();
      const isRetryable = err?.isRetryable !== false && (
        message.includes("timeout") ||
        message.includes("econnrefused") ||
        message.includes("econnreset") ||
        message.includes("network") ||
        message.includes("500") ||
        message.includes("502") ||
        message.includes("503") ||
        message.includes("429")
      );
      
      // If not retryable or last attempt, stop retrying
      if(!isRetryable || attempt === MAX_RETRIES){
        throw new Error(`TheMealDB request failed: ${String(err?.message || "Unknown error")}`);
      }
      
      // Exponential backoff before retry
      const delayMs = INITIAL_RETRY_DELAY_MS * Math.pow(2, attempt);
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
  
  throw new Error(`TheMealDB request failed: ${String(lastError?.message || "Unknown error")}`);
}

// TheMealDB Fetch Helper Functions
// Based on: https://www.themealdb.com/api/json/v1/1/

async function fetchMealById(mealId){
  const id = String(mealId || "").trim();
  if(!id){
    throw new Error("Missing meal ID");
  }
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/lookup.php?i=${encodeURIComponent(id)}`);
  return Array.isArray(payload?.meals) ? payload.meals[0] : null;
}

async function fetchMealsByName(mealName){
  const name = String(mealName || "").trim();
  if(!name){
    throw new Error("Missing meal name");
  }
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/search.php?s=${encodeURIComponent(name)}`);
  return Array.isArray(payload?.meals) ? payload.meals : [];
}

async function fetchMealsByIngredient(ingredientName){
  const ingredient = String(ingredientName || "").trim();
  if(!ingredient){
    throw new Error("Missing ingredient name");
  }
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/filter.php?i=${encodeURIComponent(ingredient)}`);
  return Array.isArray(payload?.meals) ? payload.meals : [];
}

async function fetchMealsByArea(areaName){
  const area = String(areaName || "").trim();
  if(!area){
    throw new Error("Missing area name");
  }
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/filter.php?a=${encodeURIComponent(area)}`);
  return Array.isArray(payload?.meals) ? payload.meals : [];
}

async function fetchAllAreas(){
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/list.php?a=list`);
  if(!Array.isArray(payload?.meals)){
    return [];
  }
  return payload.meals
    .map(item => String(item?.strArea || "").trim())
    .filter(Boolean);
}

async function fetchAllIngredients(){
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/list.php?i=list`);
  if(!Array.isArray(payload?.meals)){
    return [];
  }
  return payload.meals
    .map(item => String(item?.strIngredient || "").trim())
    .filter(Boolean);
}

async function fetchAllCategories(){
  const payload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/list.php?c=list`);
  if(!Array.isArray(payload?.meals)){
    return [];
  }
  return payload.meals
    .map(item => String(item?.strCategory || "").trim())
    .filter(Boolean);
}

async function fetchRecipeImageFromMealDb(recipeName){
  const name = normalizeRecipeLookupTerm(recipeName);
  if(!name){
    throw new Error("Missing recipeName");
  }

  const cacheKey = `themealdb:${name.toLowerCase()}`;
  if(generatedImageCache.has(cacheKey)){
    return generatedImageCache.get(cacheKey);
  }

  const encodedName = encodeURIComponent(name);
  let meals = await fetchMealsByName(name);
  let imageUrl = getMealDbImageFromMeals(meals, name);

  if(!imageUrl){
    const firstWord = String(name.split(/\s+/)[0] || "").trim().toLowerCase();
    if(firstWord){
      meals = await fetchMealsByIngredient(firstWord);
      imageUrl = getMealDbImageFromMeals(meals, name);
    }
  }

  if(!imageUrl){
    const firstLetter = String(name[0] || "").trim().toLowerCase();
    if(firstLetter){
      const letterPayload = await fetchJsonWithTimeout(`${THEMEALDB_BASE_URL}/search.php?f=${encodeURIComponent(firstLetter)}`);
      imageUrl = getMealDbImageFromMeals(letterPayload?.meals, name);
    }
  }

  if(!imageUrl){
    throw new Error(`No TheMealDB image found for "${name}".`);
  }

  cacheGeneratedImage(cacheKey, imageUrl);
  return imageUrl;
}

app.post("/api/auth/register", async (req, res) => {
  try{
    const email = normalizeEmail(req.body?.email);
    const fullName = normalizeFullName(req.body?.fullName);
    const password = String(req.body?.password || "");

    if(!isValidEmail(email)){
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    if(!isValidFullName(fullName)){
      return res.status(400).json({
        error: `Enter a name with at least ${AUTH_MIN_NAME_LENGTH} characters.`
      });
    }

    if(!isValidPassword(password)){
      return res.status(400).json({
        error: `Password must be at least ${AUTH_MIN_PASSWORD_LENGTH} characters.`
      });
    }

    const pool = await getAuthPool();
    const existing = await getUserByEmail(pool, email);
    if(existing){
      await recordAuthActivity(pool, {
        userId: existing.id,
        email,
        actionType: "register",
        success: false
      });
      return res.status(409).json({ error: "Email is already registered." });
    }

    const passwordHash = await hashPassword(password);
    const [result] = await pool.query(
      "INSERT INTO users (email, full_name, password_hash) VALUES (?, ?, ?)",
      [email, fullName, passwordHash]
    );

    const userId = Number(result?.insertId || 0) || null;
    await recordAuthActivity(pool, {
      userId,
      email,
      actionType: "register",
      success: true
    });

    return res.status(201).json({
      message: "Account created.",
      user: { email, fullName }
    });
  }catch(err){
    const mappedError = mapAuthServiceError(err);
    if(mappedError){
      console.error("Auth register error:", mappedError.error);
      return res.status(mappedError.status).json({ error: mappedError.error });
    }

    const safeMessage = redactSecrets(err?.message) || "Unable to create account.";
    console.error("Auth register error:", safeMessage);
    return res.status(500).json({ error: "Unable to create account right now." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try{
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if(!email || !password){
      return res.status(400).json({ error: "Enter email and password." });
    }

    const pool = await getAuthPool();
    const user = await getUserByEmail(pool, email);
    if(!user){
      await recordAuthActivity(pool, {
        email,
        actionType: "login",
        success: false
      });
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const validPassword = await verifyPassword(password, user.password_hash);
    if(!validPassword){
      await recordAuthActivity(pool, {
        userId: user.id,
        email,
        actionType: "login",
        success: false
      });
      return res.status(401).json({ error: "Invalid email or password." });
    }

    await recordAuthActivity(pool, {
      userId: user.id,
      email,
      actionType: "login",
      success: true
    });

    return res.json({
      message: "Login successful.",
      user: {
        email: user.email,
        fullName: normalizeFullName(user.full_name)
      }
    });
  }catch(err){
    const mappedError = mapAuthServiceError(err);
    if(mappedError){
      console.error("Auth login error:", mappedError.error);
      return res.status(mappedError.status).json({ error: mappedError.error });
    }

    const safeMessage = redactSecrets(err?.message) || "Unable to login.";
    console.error("Auth login error:", safeMessage);
    return res.status(500).json({ error: "Unable to login right now." });
  }
});

app.post("/api/auth/verify", async (req, res) => {
  try{
    const email = normalizeEmail(req.body?.email);

    if(!isValidEmail(email)){
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    const pool = await getAuthPool();
    const user = await getUserByEmail(pool, email);
    if(!user){
      return res.status(404).json({ error: "User not found." });
    }

    return res.json({
      verified: true,
      user: {
        email: user.email,
        fullName: normalizeFullName(user.full_name)
      }
    });
  }catch(err){
    const mappedError = mapAuthServiceError(err);
    if(mappedError){
      console.error("Auth verify error:", mappedError.error);
      return res.status(mappedError.status).json({ error: mappedError.error });
    }

    const safeMessage = redactSecrets(err?.message) || "Unable to verify user.";
    console.error("Auth verify error:", safeMessage);
    return res.status(500).json({ error: "Unable to verify user right now." });
  }
});

app.post("/api/recipes/search", async (req, res) => {
  try{
    const message = String(req.body?.message || "").trim();
    const origin = String(req.body?.origin || "").trim().slice(0, 80);
    const dietaryPreference = String(req.body?.dietaryPreference || "").trim().slice(0, 50);

    if(!message){
      return res.status(400).json({ error: "Provide at least one ingredient." });
    }

    const result = await searchRecipesByIngredients(message, origin, dietaryPreference);
    return res.json({
      provider: "themealdb",
      origin,
      dietaryPreference,
      ingredients: result.ingredients,
      reply: result.reply,
      recipes: result.recipes
    });
  }catch(err){
    const safeMessage = redactSecrets(err?.message) || "Server error calling TheMealDB recipe API.";
    console.error("Recipe search error:", safeMessage);
    return res.status(500).json({ error: safeMessage });
  }
});

app.post("/api/recipe-image", async (req, res) => {
  try{
    const recipeName = String(req.body?.recipeName || "").trim().slice(0, 100);
    if(!recipeName){
      return res.status(400).json({ error: "Missing recipeName in request body." });
    }

    const imageUrl = await fetchRecipeImageFromMealDb(recipeName);
    return res.json({
      provider: "themealdb",
      recipeName,
      imageUrl
    });
  }catch(err){
    const safeMessage = redactSecrets(err?.message) || "Server error calling TheMealDB image API.";
    console.error("Recipe image error:", safeMessage);
    const status = safeMessage.toLowerCase().includes("no themealdb image found") ? 404 : 500;
    return res.status(status).json({ error: safeMessage });
  }
});

app.listen(port, () => {
  console.log(`CookBot server running on http://localhost:${port}`);
});
