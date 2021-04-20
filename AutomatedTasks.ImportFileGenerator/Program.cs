using AutomatedTasks.ImportFileGenerator.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Linq;
using NPOI.XSSF.UserModel;
using NPOI.SS.UserModel;

var previousDateFile = File.ReadAllText($@"[INSERT FILENAME HERE].json");
var currentDateFile = File.ReadAllText($@"[INSERT FILENAME HERE].json");

var previousDateDefects = JsonSerializer.Deserialize<List<AppSecItem>>(previousDateFile);
var currentDateDefects = JsonSerializer.Deserialize<List<AppSecItem>>(currentDateFile);

var newItems = currentDateDefects.Where(cd => !previousDateDefects.Any(pd => pd.Id.Equals(cd.Id))).ToList();
var suppressedItems = previousDateDefects.Where(pd => !currentDateDefects.Any(cd => cd.Id.Equals(pd.Id))).ToList();
var carriedOverItems = previousDateDefects.Where(pd => currentDateDefects.Any(cd => cd.Id.Equals(pd.Id))).ToList();
var reintroduced = currentDateDefects.Where(cd => cd.ScanStatus.Equals("REINTRODUCED", StringComparison.InvariantCultureIgnoreCase)).ToList();

using (var fs = new FileStream(@"C:\Temp\UVMS\DefectsImport.xlsx", FileMode.Create, FileAccess.Write))
{
    IWorkbook workbook;
    workbook = new XSSFWorkbook();
    ISheet excelSheet = workbook.CreateSheet("Security Defects");

    IRow row = excelSheet.CreateRow(0);
    row.CreateCell(0).SetCellValue("AssetType");
    row.CreateCell(1).SetCellValue("Name");
    row.CreateCell(2).SetCellValue("Scope");
    row.CreateCell(3).SetCellValue("Description");
    row.CreateCell(4).SetCellValue("Estimate");
    row.CreateCell(5).SetCellValue("Priority");
    row.CreateCell(6).SetCellValue("Timebox");
    row.CreateCell(7).SetCellValue("Team");
    row.CreateCell(8).SetCellValue("Parent");

    var rowCount = 1;

    var groupedNewItems = newItems.Distinct(new AppSecItemComparer()).ToList();

    foreach (var item in groupedNewItems)
    {
        row = excelSheet.CreateRow(rowCount);
        row.CreateCell(0).SetCellValue("Defect");
        row.CreateCell(1).SetCellValue($"[RELEASE] [{item.Severity}] [{item.Source}] {item.Category} ({newItems.Count(i => i.Category.Equals(item.Category))} items found on {DateTime.Now.Date.ToString("yyyy-MM-dd")})");
        row.CreateCell(2).SetCellValue("[RELEASE]");
        row.CreateCell(3).SetCellValue($"See Fortify SSC Dahsboard {item.UAID} {item.Version}");
        row.CreateCell(4).SetCellValue("");
        row.CreateCell(5).SetCellValue("High");
        row.CreateCell(6).SetCellValue("[SPRINT]");
        row.CreateCell(7).SetCellValue("[TEAM]");
        row.CreateCell(8).SetCellValue("[PARENT]");

        rowCount++;
    }

    workbook.Write(fs);
}
    
