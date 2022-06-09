using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Nest_Backend.Models;
using Nest_Backend.Utilies;
using Nest_Backend.ViewModels.AuthLogin;
using System;
using System.Threading.Tasks;

namespace Nest_Backend.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult SingIn()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> SingIn(SingInVM singIn, string ReturnUrl)
        {
            AppUser user;
            if (singIn.UsernameOrEmail.Contains("@"))
            {
                user = await _userManager.FindByEmailAsync(singIn.UsernameOrEmail);
            }
            else
            {
                user = await _userManager.FindByNameAsync(singIn.UsernameOrEmail);
            }
            if (user == null)
            {
                ModelState.AddModelError("", "Login or Password is incorrect");
                return View(singIn);
            }
            var result = await _signInManager.PasswordSignInAsync(user, singIn.Password, singIn.RememberMe, true);
            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "You have failed the test. Please wait");
                return View(singIn);
            }
            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Login or Password is incorrect");
                return View(singIn);
            }
            if (ReturnUrl != null) return LocalRedirect(ReturnUrl);
            return RedirectToAction("Index", "Home");
        }
        public IActionResult Register()
        {

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Register(RegisterVM registerVM)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }
            AppUser nUser = new AppUser()
            {

                Name = registerVM.FirstName,
                Surname = registerVM.LastName,
                Email = registerVM.Email,
                UserName = registerVM.Username
            };
            IdentityResult result = await _userManager.CreateAsync(nUser, registerVM.Password);
            if (!result.Succeeded)
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError("", item.Description);
                }
            }
            await _userManager.AddToRoleAsync(nUser, UserRoles.Member.ToString());
            return RedirectToAction("Index", "Home");
        }
        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Register));
        }
        public async Task CreateRoles()
        {
            foreach (var item in Enum.GetValues(typeof(UserRoles)))
            {
                if (!await _roleManager.RoleExistsAsync(item.ToString())) await _roleManager.CreateAsync(new IdentityRole(item.ToString()));

            }
        }
    }
}
