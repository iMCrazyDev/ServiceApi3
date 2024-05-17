using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Microsoft.IdentityModel.Tokens;
using ServiceApi3;
using static ServiceApi3.UserRepository;

var uc = new UserContext();
uc.Database.EnsureCreated();
uc.SaveChanges();
var builder = WebApplication.CreateSlimBuilder(args);
builder.WebHost.UseKestrel(kestrelOptions =>
{
    kestrelOptions.ListenAnyIP(5000);
});

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "";// "http://mircroenv.tech";
        options.Audience = AuthOptions.AUDIENCE;
        options.ClaimsIssuer = AuthOptions.ISSUER;
        options.RequireHttpsMetadata = false;
        options.MetadataAddress = null;
        options.TokenValidationParameters = new TokenValidationParameters
        {

            ValidateIssuer = true,
            ValidIssuer = AuthOptions.ISSUER,
            ValidateAudience = true,
            ValidAudience = AuthOptions.AUDIENCE,
            ValidateLifetime = true,
            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
            ValidateIssuerSigningKey = true,
        };
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyHeader() 
               .AllowAnyMethod();
    });
});
builder.Services.AddAuthorization();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

var userApi = app.MapGroup("/user");

userApi.MapGet("/validate_token", [Authorize] () => Results.Ok());

userApi.MapPost("/login", ([FromBody] LoginData loginData) =>
{
    var auth = new UserContext();
    var res = auth.Login(loginData);
    return res.result ? Results.Ok(res) : Results.NotFound(res);
});

userApi.MapPost("/register", ([FromBody] RegisterData registerData) =>
{
    var auth = new UserContext();
    var res = auth.Register(registerData);
    return res.result ? Results.Ok(res) : Results.NotFound(res);
});

var masterApi = app.MapGroup("/master");

masterApi.MapGet("/for", [Authorize] (HttpContext context, [FromQuery] uint master_id) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetMasterById(master_id);
    return res.User.Id == userId ? Results.Ok() : Results.NotFound();
});

masterApi.MapGet("/set_location", 
    (HttpContext context, [FromQuery] string token, [FromQuery] string hardware_name, [FromQuery] string guid, [FromQuery] double latitude, [FromQuery] double longitude) =>
{
    var user = new UserContext();
    var master = user.GetMasterByToken(token);
    if (master == null)
    {
        return Results.NotFound();
    }

    var slave = user.GetOrCreateSlaveByMasterAndGuid(master.Id, guid, hardware_name);
    slave.Latitude = latitude;
    slave.Longitude = longitude;
    user.SaveChanges();
    return Results.Ok();
});

masterApi.MapPost("/push", (HttpContext context, [FromQuery] string token, [FromBody] PushData[] registerData) =>
{
    var user = new UserContext();
    var master = user.GetMasterByToken(token);
    if (master == null) 
    {
        return Results.NotFound();
    }

    foreach (var t in registerData)
    {
        try
        {
            var guid = t.guid;
            var slave = user.GetOrCreateSlaveByMasterAndGuid(master.Id, guid, t.hardware_name);
            foreach (var r in t.values)
            {
                foreach (var z in r.sensor_data)
                {
                    user.PushData(slave, r.sensor_name + "_" + z.sensor_name, r.status, z.sensor_value, z.units);
                }
            }
        }
        catch { }
    }
    return Results.Ok();
});

/*masterApi.MapPost("/grant_access", (HttpContext context, [FromQuery] string token, [FromBody] PushData registerData) => TODO
{
    var user = new UserContext();
    var res = user.GetMasterByToken(token);
    if (res == null)
    {
        return Results.NotFound();
    }


    return Results.Ok();
});*/

masterApi.MapGet("/validate_token", (HttpContext context, [FromQuery] string token) =>
{
    var user = new UserContext();
    var res = user.GetMasterByToken(token);
    return res == null ? Results.NotFound() : Results.Ok();
});

masterApi.MapGet("/rename", [Authorize] (HttpContext context, [FromQuery] uint master_id, [FromQuery] string name) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetMasterById(master_id);
    if (res.User.Id == userId)
    {
        user.RenameMastersByUser(res.Id, name);
        return Results.Ok();
    }
    return Results.BadRequest();
});

masterApi.MapGet("/sensor_rename", [Authorize] (HttpContext context, [FromQuery] uint master_id, [FromQuery] uint sensor_id, [FromQuery] string name) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetMasterById(master_id);
    if (res.User.Id == userId)
    {
        var slave = user.GetSlaveById(sensor_id);
        if (slave.Master.Id == res.Id)
        {
            user.RenameSlave(name, slave);
            return Results.Ok();
        }
        return Results.BadRequest();
    }
    return Results.BadRequest();
});

masterApi.MapGet("/token", [Authorize] (HttpContext context, [FromQuery] uint master_id) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetToken(master_id, userId);
    return res == "error" ? Results.BadRequest(res) : Results.Ok(res);
});

masterApi.MapGet("/create", [Authorize] (HttpContext context, [FromQuery] string? name) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.CreateMaster(name, user.GetUserById(userId));
    var resLine = new GetMasterLine(res.Item1, res.Item2);
    return res.Item1 ? Results.Ok(resLine) : Results.BadRequest(resLine);
});

masterApi.MapGet("/list", [Authorize] (HttpContext context) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetMastersByUser(userId).Select(x => new MasterLine(x.Id, x.Name));
    return Results.Ok(res);
});


masterApi.MapGet("/sensors", [Authorize] (HttpContext context, [FromQuery] uint master_id) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetSlavesByUserAndMaster(userId, master_id)
        .Select(x=> new SlaveLine(x.Id, x.ToString(), x.Longitude, x.Latitude));
    return Results.Ok(res);
});

masterApi.MapGet("/data/names", [Authorize] 
(HttpContext context, [FromQuery] long from, [FromQuery] long to, [FromQuery] uint master_id, [FromQuery] uint sensor_id) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetDataNames(from, to, master_id, sensor_id, userId);
    return Results.Ok(res);
});

masterApi.MapGet("/last_timestamp", [Authorize] (HttpContext context, [FromQuery] uint master_id) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var m = user.GetMasterById(master_id);
    try
    {
        if (m.User.Id != userId)
        {
            throw new Exception("Invalid master");
        }
        var res = user.GetLastTimestampByUser(master_id);
        return Results.Ok(res);
    }
    catch
    {
        return Results.BadRequest();
    }
});

masterApi.MapGet("/data", [Authorize] 
    (HttpContext context, [FromQuery] long from, [FromQuery] long to,
    [FromQuery] uint master_id, [FromQuery] uint sensor_id, [FromQuery] string name) =>
{
    var userId = Auth.GetUserIdByContext(context);
    if (userId == 0)
    {
        return Results.Unauthorized();
    }
    var user = new UserContext();
    var res = user.GetData(from, to, master_id, sensor_id, userId, name)
    .Select(x => new SensorLine(x.Id, x.Timestamp, x.Value, x.Status, x.Name, x.Units));
    return Results.Ok(res);
});

/*userApi.MapGet("/{id}", (int id) =>
    sampleTodos.FirstOrDefault(a => a.Id == id) is { } todo
        ? Results.Ok(todo)
        : Results.NotFound());*/

/*var sampleTodos = new Todo[] {
    new(1, "Walk the dog"),
    new(2, "Do the dishes", DateOnly.FromDateTime(DateTime.Now)),
    new(3, "Do the laundry", DateOnly.FromDateTime(DateTime.Now.AddDays(1))),
    new(4, "Clean the bathroom"),
    new(5, "Clean the car", DateOnly.FromDateTime(DateTime.Now.AddDays(2)))
};

var todosApi = app.MapGroup("/todos");
todosApi.MapGet("/", () => sampleTodos);
todosApi.MapGet("/{id}", (int id) =>
    sampleTodos.FirstOrDefault(a => a.Id == id) is { } todo
        ? Results.Ok(todo)
        : Results.NotFound());*/

app.Run();
