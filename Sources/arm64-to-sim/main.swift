import Foundation
import MachO

// support checking for Mach-O `cmd` and `cmdsize` properties
extension Data {
    var loadCommand: UInt32 {
        let lc: load_command = withUnsafeBytes { $0.load(as: load_command.self) }
        return lc.cmd
    }
    
    var commandSize: Int {
        let lc: load_command = withUnsafeBytes { $0.load(as: load_command.self) }
        return Int(lc.cmdsize)
    }
    
    func asStruct<T>(fromByteOffset offset: Int = 0) -> T {
        return withUnsafeBytes { $0.load(fromByteOffset: offset, as: T.self) }
    }
}

extension Array where Element == Data {
    func merge() -> Data {
        return reduce(into: Data()) { $0.append($1) }
    }
}

// support peeking at Data contents
extension FileHandle {
    func peek(upToCount count: Int) throws -> Data? {
        // persist the current offset, since `upToCount` doesn't guarantee all bytes will be read
        let originalOffset = offsetInFile
        let data = try read(upToCount: count)
        try seek(toOffset: originalOffset)
        return data
    }
}

enum Transmogrifier {
    private static func readBinary(atPath path: String) -> (Data, [Data], Data) {
        guard let handle = FileHandle(forReadingAtPath: path) else {
            fatalError("Cannot open a handle for the file at \(path). Aborting.")
        }
        
        // chop up the file into a relevant number of segments
        let headerData = try! handle.read(upToCount: MemoryLayout<mach_header_64>.stride)!
        
        let header: mach_header_64 = headerData.asStruct()
        if header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 {
            fatalError("The file is not a correct arm64 binary. Try thinning (via lipo) or unarchiving (via ar) first.")
        }
        
        let loadCommandsData: [Data] = (0..<header.ncmds).map { _ in
            let loadCommandPeekData = try! handle.peek(upToCount: MemoryLayout<load_command>.stride)
            return try! handle.read(upToCount: Int(loadCommandPeekData!.commandSize))!
        }
        
        let programData = try! handle.readToEnd()!
        
        try! handle.close()
        
        return (headerData, loadCommandsData, programData)
    }

    private static func applyOffset<T: UnsignedInteger>(_ value: T, _ offset: Int32) -> T {
        if offset < 0 {
            let absOffset = T(abs(offset))
            return absOffset > value ? 0 : value - absOffset
        }
        return value + T(offset)
    }
    
    private static func updateSegment64(_ data: Data, _ offset: Int32) -> Data {
        // decode both the segment_command_64 and the subsequent section_64s
        var segment: segment_command_64 = data.asStruct()
        
        let sections: [section_64] = (0..<Int(segment.nsects)).map { index in
            let offset = MemoryLayout<segment_command_64>.stride + index * MemoryLayout<section_64>.stride
            return data.asStruct(fromByteOffset: offset)
        }
        
        // shift segment information by the offset
        segment.fileoff = applyOffset(segment.fileoff, offset)
        segment.filesize = applyOffset(segment.filesize, offset)
        segment.vmsize = applyOffset(segment.vmsize, offset)
        
        let offsetSections = sections.map { section -> section_64 in
            let sectionType = section.flags & UInt32(SECTION_TYPE)
            switch Int32(sectionType) {
            case S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL:
                return section
            case _: break
            }

            var section = section
            section.offset = applyOffset(section.offset, offset)
            if section.reloff > 0 {
                section.reloff = applyOffset(section.reloff, offset)
            } else {
                section.reloff = 0
            }
            return section
        }
        
        var datas = [Data]()
        datas.append(Data(bytes: &segment, count: MemoryLayout<segment_command_64>.stride))
        datas.append(contentsOf: offsetSections.map { section in
            var section = section
            return Data(bytes: &section, count: MemoryLayout<section_64>.stride)
        })
        
        return datas.merge()
    }
    
    private static func makeBuildVersion(minos: UInt32, sdk: UInt32) -> Data {
        var command = build_version_command(cmd: UInt32(LC_BUILD_VERSION),
                                            cmdsize: UInt32(MemoryLayout<build_version_command>.stride),
                                            platform: UInt32(PLATFORM_IOSSIMULATOR),
                                            minos: minos << 16 | 0 << 8 | 0,
                                            sdk: sdk << 16 | 0 << 8 | 0,
                                            ntools: 0)
        
        return Data(bytes: &command, count: MemoryLayout<build_version_command>.stride)
    }
    
    private static func updateDataInCode(_ data: Data, _ offset: Int32) -> Data {
        var command: linkedit_data_command = data.asStruct()
        command.dataoff = applyOffset(command.dataoff, offset)
        return Data(bytes: &command, count: data.commandSize)
    }
    
    private static func updateSymTab(_ data: Data, _ offset: Int32) -> Data {
        var command: symtab_command = data.asStruct()
        command.stroff = applyOffset(command.stroff, offset)
        command.symoff = applyOffset(command.symoff, offset)
        return Data(bytes: &command, count: data.commandSize)
    }
    
    static func processBinary(atPath path: String, minos: UInt32 = 13, sdk: UInt32 = 13) {
        guard CommandLine.arguments.count > 1 else {
            fatalError("Please add a path to command!")
        }
        let (headerData, loadCommandsData, programData) = readBinary(atPath: path)

        var hasVersionMin = false
        var buildVersionSize: UInt32 = 0
        for lc in loadCommandsData {
            let cmd = Int32(lc.loadCommand)
            if cmd == LC_VERSION_MIN_IPHONEOS {
                hasVersionMin = true
            } else if cmd == LC_BUILD_VERSION {
                buildVersionSize = UInt32(lc.count)
            }
        }
        let hasBuildVersion = (buildVersionSize > 0)

        var offset: Int32 = 0
        if hasBuildVersion && hasVersionMin {
            fatalError("has LC_BUILD_VERSION and LC_VERSION_MIN_IPHONEOS")
        } else if !hasBuildVersion && !hasVersionMin {
            fatalError("doesn't have LC_BUILD_VERSION or LC_VERSION_MIN_IPHONEOS")
        } else if hasVersionMin {
            offset = Int32(MemoryLayout<build_version_command>.stride - MemoryLayout<version_min_command>.stride)
        } else {
            offset = Int32(MemoryLayout<build_version_command>.stride) - Int32(buildVersionSize)
        }

        let editedCommands = loadCommandsData
            .map { (lc) -> Data in
                switch Int32(lc.loadCommand) {
                case LC_SEGMENT_64:
                    return offset == 0 ? lc : updateSegment64(lc, offset)
                case LC_VERSION_MIN_IPHONEOS:
                    return makeBuildVersion(minos: minos, sdk: sdk)
                case LC_DATA_IN_CODE, LC_LINKER_OPTIMIZATION_HINT:
                    return offset == 0 ? lc : updateDataInCode(lc, offset)
                case LC_SYMTAB:
                    return offset == 0 ? lc : updateSymTab(lc, offset)
                case LC_BUILD_VERSION:
                    return makeBuildVersion(minos: minos, sdk: sdk)
                default:
                    return lc
                }
            }

        let editedCommandsData = editedCommands.merge()
        
        var header: mach_header_64 = headerData.asStruct()
        header.sizeofcmds = UInt32(editedCommandsData.count)
        
        // reassemble the binary
        let reworkedData = [
            Data(bytes: &header, count: MemoryLayout<mach_header_64>.stride),
            editedCommandsData,
            programData
        ].merge()
        
        // save back to disk
        try! reworkedData.write(to: URL(fileURLWithPath: path))
    }
}

let binaryPath = CommandLine.arguments[1]
let minos = UInt32(CommandLine.arguments[2]) ?? 13
let sdk = UInt32(CommandLine.arguments[3]) ?? 13
Transmogrifier.processBinary(atPath: binaryPath, minos: minos, sdk: sdk)
