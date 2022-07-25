using Authorization.Data;
using Authorization.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace Authorization.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UsersDbContext _uDb;

        public HomeController(ILogger<HomeController> logger, UsersDbContext UDb)
        {
            _uDb = UDb;
            _logger = logger;
        }

        [Authorize]
        public IActionResult Index()
        {
            if (_uDb.Users.Find(User.Identity.Name).isBanned)
                return RedirectToAction("Ban");

            return View();
        }

        [Authorize]
        public IActionResult Users()
        {
            if (_uDb.Users.Find(User.Identity.Name).isBanned)
                return RedirectToAction("Ban");

            IEnumerable<User> objUsersList = _uDb.Users;
            return View(objUsersList);
        }

        [HttpGet("login")]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Validate(string username, string password, string returnUrl)
        {

            var user = _uDb.Users.Find(username);

            
            if (user == null)
            {
                TempData["Error"] = "User not found!";
                return RedirectToAction("Login");
            }

            if (user.isBanned)
                return RedirectToAction("Banned");

            if (user.UserName == username && user.Password == password)
            {
                var claims = new List<Claim>();
                claims.Add(new Claim("username", username));
                claims.Add(new Claim("email", user.Email));
                claims.Add(new Claim(ClaimTypes.NameIdentifier, username));
                claims.Add(new Claim(ClaimTypes.Name, username));
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var claimsPrinciple = new ClaimsPrincipal(claimsIdentity);
                user.LastLogin = DateTime.Now;
                await HttpContext.SignInAsync(claimsPrinciple);
                _uDb.Users.Update(user);
                _uDb.SaveChanges();
                TempData["Success"] = "Successfully logged in!";

                return RedirectToAction("Index");
            }

            return RedirectToAction("Login");

        }

        [HttpPost]
        public IActionResult Signup(User obj)
        {
            obj.LastLogin = DateTime.Now;
            obj.Registered = DateTime.Now;
            if (ModelState.IsValid)
            {
                var tmp = _uDb.Users.Find(obj.UserName);
                if (tmp == null)
                {
                    _uDb.Users.Add(obj);
                    _uDb.SaveChanges();
                    TempData["Success"] = "Registered successfully";
                }
                else
                    TempData["Error"] = "User already exists!";


            }
            
            return RedirectToAction("Login");
        }

        [Authorize]
        public IActionResult Ban()
        {
            var tmp = _uDb.Users.Find(User.Identity.Name);
            tmp.isBanned = true;
            _uDb.Users.Update(tmp);
            _uDb.SaveChanges();
            return RedirectToAction("Logout");
        }

        public IActionResult Banned()
        {
            return View();
        }

        [Authorize]
        public IActionResult Delete()
        {
            var tmp = _uDb.Users.Find(User.Identity.Name);
            _uDb.Users.Remove(tmp);
            _uDb.SaveChanges();
            return RedirectToAction("Logout");
        }

        [Authorize]
        [HttpPost]
        public IActionResult DeleteUser(List<string> usernames)
        {
            foreach (string username in usernames)
            {
                var tmp = _uDb.Users.Find(username);
                _uDb.Users.Remove(tmp);
                _uDb.SaveChanges();
            }
            
            if (usernames.Contains(User.Identity.Name))
                return RedirectToAction("Logout");

            return RedirectToAction("Users");
        }

        [Authorize]
        [HttpPost]
        public IActionResult BanUser(List<string> usernames)
        {
            foreach (string username in usernames)
            {
                var tmp = _uDb.Users.Find(username);
                tmp.isBanned = true;
                _uDb.Users.Update(tmp);
                _uDb.SaveChanges();
            }

            if (usernames.Contains(User.Identity.Name))
                return RedirectToAction("Logout");

            return RedirectToAction("Users");
        }

        [Authorize]
        [HttpPost]
        public IActionResult DeBanUser(List<string> usernames)
        {
            foreach (string username in usernames)
            {
                var tmp = _uDb.Users.Find(username);
                tmp.isBanned = false;
                _uDb.Users.Update(tmp);
                _uDb.SaveChanges();
            }
            if (usernames.Contains(User.Identity.Name))
                return RedirectToAction("Logout");

            return RedirectToAction("Users");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}