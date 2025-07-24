using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using ApiAutenticacionJWT.DTOs;
using ApiAutenticacionJWT.Models;
using ApiAutenticacionJWT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ApiAutenticacionJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly TokenService _tokenService;

        public AuthController(UserManager<ApplicationUser> userManager,
                              RoleManager<IdentityRole> roleManager,
                              TokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var userExists = await _userManager.FindByEmailAsync(dto.Email);
            if (userExists != null)
                return BadRequest(new { message = "El usuario ya existe" });

            ApplicationUser user = new ApplicationUser
            {
                FullName = dto.FullName,
                Email = dto.Email,
                UserName = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
                return BadRequest(new { message = result.Errors.FirstOrDefault()?.Description });

            if (!await _roleManager.RoleExistsAsync(dto.Rol))
                await _roleManager.CreateAsync(new IdentityRole(dto.Rol));

            await _userManager.AddToRoleAsync(user, dto.Rol);

            return Ok(new
            {
                message = "Usuario registrado correctamente",
                userId = user.Id
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized("Credenciales inválidas");

            var roles = await _userManager.GetRolesAsync(user);
            var token = _tokenService.CreateToken(user, roles);

            return Ok(new { token });
        }
        [Authorize]
        [HttpGet("debug")]
        public IActionResult DebugUserInfo()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            return Ok(claims);
        }


        [Authorize]
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            // Obtener el usuario directamente del contexto de autenticación
            var user = await _userManager.GetUserAsync(User);

            if (user == null)
            {
                return NotFound(new
                {
                    isSuccess = false,
                    message = "User not found",
                    DebugInfo = new
                    {
                        User.Identity?.Name,
                        Claims = User.Claims.Select(c => new { c.Type, c.Value })
                    }
                });
            }

            // Obtener los roles del usuario
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new UserDetailDto
            {
                Email = user.Email,
                FullName = user.FullName,
                Rol = roles.FirstOrDefault() // Usar el primer rol o null si no tiene
            });
        }

        [HttpGet("users")]
        public async Task<ActionResult<IEnumerable<UsersDto>>> GetUsers()
        {
            var users = await _userManager.Users
                .ToListAsync(); // Primero obtenemos los usuarios

            var userDtos = new List<UsersDto>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDtos.Add(new UsersDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Rol = roles.FirstOrDefault() // O puedes convertir todos a string
                });
            }

            return Ok(userDtos);
        }


        [Authorize(Roles = "admin")] // Asegura que solo administradores puedan eliminar
        [HttpDelete("delete/{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            try
            {
                // Verificar que el usuario existe
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    return NotFound(new
                    {
                        isSuccess = false,
                        message = "Usuario no encontrado"
                    });
                }

                // Eliminar roles asignados primero (opcional, dependiendo de tu modelo)
                var userRoles = await _userManager.GetRolesAsync(user);
                if (userRoles.Any())
                {
                    await _userManager.RemoveFromRolesAsync(user, userRoles);
                }

                // Eliminar el usuario
                var result = await _userManager.DeleteAsync(user);

                if (!result.Succeeded)
                {
                    return BadRequest(new
                    {
                        isSuccess = false,
                        message = "Error al eliminar el usuario",
                        errors = result.Errors.Select(e => e.Description)
                    });
                }

                return Ok(new
                {
                    isSuccess = true,
                    message = "Usuario eliminado correctamente"
                });
            }
            catch (Exception ex)
            {
                // Loggear el error (implementa un logger)
                return StatusCode(500, new
                {
                    isSuccess = false,
                    message = "Error interno del servidor",
                    error = ex.Message
                });
            }
        }
    }
}

