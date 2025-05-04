using M183.Controllers.Dto;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class NewsController : ControllerBase
    {
        private readonly TimeZoneInfo tzi = TimeZoneInfo.FindSystemTimeZoneById("Central Europe Standard Time");
        private readonly NewsAppContext _context;
        private readonly ILogger<UserController> _logger;

        public NewsController(NewsAppContext context, ILogger<UserController> logger)
        {
            _context = context;
            _logger = logger;
        }

        private News SetTimezone(News news)
        {
            news.PostedDate = TimeZoneInfo.ConvertTimeFromUtc(news.PostedDate, tzi);
            return news;
        }

        /// <summary>
        /// Retrieve all news entries ordered by PostedDate descending
        /// </summary>
        /// <response code="200">All news entries</response>
        [HttpGet]
        [ProducesResponseType(200)]
        public ActionResult<List<News>> GetAll()
        {
            try
            {
                return Ok(_context.News
                    .Include(n => n.Author)
                    .OrderByDescending(n => n.PostedDate)
                    .ToList()
                    .Select(SetTimezone));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving news");
                return StatusCode(500, "Internal server error");
            }
        }

        /// <summary>
        /// Retrieve a specific news entry by id
        /// </summary>
        /// <param name="id" example="123">The news id</param>
        /// <response code="200">News retrieved</response>
        /// <response code="404">News not found</response>
        [HttpGet("{id}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public ActionResult<News> GetById(int id)
        {
            try
            {
                News? news = _context.News
                    .Include(n => n.Author)
                    .FirstOrDefault(n => n.Id == id);

                if (news == null)
                {
                    _logger.LogWarning("Get News Failure: News item not found for ID {NewsId}", id);
                    return NotFound();
                }
                return Ok(SetTimezone(news));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving news with ID {NewsId}", id);
                return StatusCode(500, "An error occurred while retrieving the news item.");
            }
        }

        /// <summary>
        /// Create a news entry
        /// </summary>
        /// <response code="201">News successfully created</response>
        [HttpPost]
        [ProducesResponseType(201)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(500)]
        public ActionResult Create(NewsDto request)
        {
            if (request == null)
            {
                _logger.LogWarning("News Create Attempt: Bad request - request body was null.");
                return BadRequest("Request body cannot be null.");
            }

            var newNews = new News();

            try
            {
                _context.News.Add(newNews);
                _context.SaveChanges(); // Save changes to generate the ID

                // Log success with the generated ID
                 _logger.LogInformation("News Created: News item {NewsId} created by User ID {UserId}", newNews.Id, request.AuthorId);

                // Return the created object, applying timezone for the response
                return CreatedAtAction(nameof(GetById), new { id = newNews.Id}, SetTimezone(newNews));
            }
            catch (DbUpdateException ex)
            {
                 _logger.LogError(ex, "News Create Failure: Database error occurred for User ID {UserId}", request.AuthorId);
                return StatusCode(500, "A database error occurred while creating the news item.");
            }
             catch (Exception ex)
            {
                 _logger.LogError(ex, "News Create Failure: Unexpected error occurred for User ID {UserId}", request.AuthorId);
                return StatusCode(500, "An unexpected error occurred while creating the news item.");
            }
        }

        /// <summary>
        /// Update a specific news by id
        /// </summary>
        /// <param name="id" example="123">The news id</param>
        /// <response code="200">News retrieved</response>
        /// <response code="404">News not found</response>
        [HttpPatch("{id}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public ActionResult Update(int id, NewsDto request)
        {
            if (request == null)
            {
                _logger.LogWarning("News Create Attempt: Bad request - request body was null.");
                return BadRequest("Request body cannot be null.");
            }

            try
            {
                var news = _context.News.Find(id);
                if (news == null)
                {
                    _logger.LogWarning("News Update Failure: News item not found for ID {NewsId}, attempted by User ID {UserId}", id, request.AuthorId);
                        return NotFound(string.Format("News {0} not found", id));
                }

                news.Header = request.Header;
                news.Detail = request.Detail;
                news.AuthorId = request.AuthorId;
                news.IsAdminNews = request.IsAdminNews;

                _context.News.Update(news);
                _context.SaveChanges();

                _logger.LogInformation("News Updated: News item {NewsId} updated by User ID {UserId}", id, request.AuthorId);
                return Ok("News updated successfully.");
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "News Update Failure: Database error occurred for User ID {UserId}", request.AuthorId);
                return StatusCode(500, "A database error occurred while updating the news item.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "News Update Failure: Unexpected error occurred for User ID {UserId}", request.AuthorId);
                return StatusCode(500, "An unexpected error occurred while updating the news item.");
            }
        }

        /// <summary>
        /// Delete a specific news by id
        /// </summary>
        /// <param name="id" example="123">The news id</param>
        /// <response code="200">News deleted</response>
        /// <response code="404">News not found</response>
        [HttpDelete("{id}")]
        [ProducesResponseType(200)]
        [ProducesResponseType(404)]
        public ActionResult Delete(int id)
        {
            try
            {
                var news = _context.News.Find(id);
                if (news == null)
                {
                    _logger.LogWarning("News Delete Failure: News item not found for ID {NewsId}", id);
                    return NotFound(string.Format("News {0} not found", id));
                }




                _context.News.Remove(news);
                _context.SaveChanges();

                _logger.LogInformation("News Deleted: News item {NewsId} deleted", id);
                return Ok("News deleted successfully.");
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "News Delete Failure: Database error occurred for News ID {NewsId}", id);
                return StatusCode(500, "A database error occurred while deleting the news item.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "News Delete Failure: Unexpected error occurred for News ID {NewsId}", id);
                return StatusCode(500, "An unexpected error occurred while deleting the news item.");
            }
        }
    }
}
