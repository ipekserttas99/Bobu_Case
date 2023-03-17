using JWTAndIdentityExample.Auth;
using JWTAndIdentityExample.Auth.Entities;
using JWTAndIdentityExample.Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JWTAndIdentityExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = UserRoles.Parent)]
    public class ParentsController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public ParentsController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ApplicationDbContext context,
            IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpGet]
        [Route("EbeveyneBagliKullanicilariGetir")]
        public async Task<IActionResult> GetParentsUsers()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var c = _context.Users.Where(x => x.Parents.Contains(_context.Parents.FirstOrDefault(x => x.Id == userId))).ToList();
            if (c is null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Hata", Message = "Bu ebeveyne bağlı kullanıcı yok!" });
            }
            return Ok(c);
            
        }

        [HttpPost]
        [Route("KullaniciyaEbeveynEkle")]
        public async Task<IActionResult> AddParentToUser(string userEmail)
        {
            var aa = _context.Users.FirstOrDefault(x => x.Email == userEmail);
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var bb = _context.Parents.FirstOrDefault(x => x.Id == userId);
            if (aa != null && bb != null)
            {
                aa.Parents = new List<Parent>();
                aa.Parents.Add(bb);
                await _context.SaveChangesAsync();
                return Ok(new Response { Status = "Success", Message = "Ebeveyn kullanıcı ile ilişkilendirildi!" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Hata", Message = "Bu ebeveyne bağlı kullanıcı yok!" });
        }

        [HttpPut]
        [Route("EbeveyneAitKullaniciyiGuncelle")]
        public async Task<IActionResult> UpdateUser([FromBody] UserUpdateDto user)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var bb = _context.Parents.FirstOrDefault(x => x.Id == userId);
            var aa = _context.Users.Where(x => x.Parents.Contains(bb)).AsNoTracking().FirstOrDefault();
            
            
            if (aa != null && bb != null)
            {
                var newUser = new User()
                {
                    Email = user.Email == "string" ? aa.Email : user.Email,
                    Id = aa.Id,
                    Name = user.Name == "string" ? aa.Name : user.Name,
                    Parents = aa.Parents
                };

                _context.Users.Update(newUser);
                await _context.SaveChangesAsync();
                return Ok(new Response { Status = "Başarılı", Message = "Ebeveyne ait kullanıcı güncellendi!" });
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Hata", Message = "Bu ebeveyne bağlı kullanıcı yok!" });
        }
    }
}
