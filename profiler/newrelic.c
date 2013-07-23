#include <mono/metadata/profiler.h>
#include <mono/metadata/assembly.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <expat.h>
#include <assert.h>

char *strdup(const char *s);
int asprintf(char **strp, const char *fmt, ...);

#define METHOD_HEADER_TINY_FORMAT 0x2
#define METHOD_HEADER_FAT_FORMAT 0x3

#define MAX_ARGUMENTS 4

static const unsigned char METHOD_HEADER_FORMAT_MASK = 0x3;
static const unsigned char METHOD_HEADER_MORE_SECTS = 0x8;
static const unsigned char METHOD_HEADER_SECTION_MORE_SECTS = 0x80;
static const unsigned char METHOD_HEADER_SECTION_FAT_FORMAT = 0x40;
static const unsigned char METHOD_HEADER_SECTION_EHTABLE = 0x1;

static const unsigned char INSTRUCTION_NOP = 0x00;
static const unsigned char INSTRUCTION_LDARG_0 = 0x02;
static const unsigned char INSTRUCTION_LDLOC_0 = 0x06;
static const unsigned char INSTRUCTION_STLOC_0 = 0x0A;
static const unsigned char INSTRUCTION_LDARG_S = 0x0E;
static const unsigned char INSTRUCTION_LDLOC_S = 0x11;
static const unsigned char INSTRUCTION_STLOC_S = 0x13;
static const unsigned char INSTRUCTION_LDNULL = 0x14;
static const unsigned char INSTRUCTION_LDC_I4_0 = 0x16;
static const unsigned char INSTRUCTION_LDC_I4 = 0x20;
static const unsigned char INSTRUCTION_DUP = 0x25;
static const unsigned char INSTRUCTION_CALL = 0x28;
static const unsigned char INSTRUCTION_RET = 0x2A;
static const unsigned char INSTRUCTION_BR_S = 0x2B;
static const unsigned char INSTRUCTION_BRFALSE_S = 0x2C;
static const unsigned char INSTRUCTION_BR = 0x38;
static const unsigned char INSTRUCTION_LDSTR = 0x72;
static const unsigned char INSTRUCTION_BOX = 0x8C;
static const unsigned char INSTRUCTION_NEWARR = 0x8D;
static const unsigned char INSTRUCTION_STELEM_REF = 0xA2;
static const unsigned char INSTRUCTION_LEAVE_S = 0xDE;

static const uint16_t INSTRUCTION_RETHROW = 0x1AFE;

typedef struct _Configuration Configuration;
typedef struct _SearchableConfiguration SearchableConfiguration;
typedef struct _MethodConfiguration MethodConfiguration;
typedef struct _ClassConfiguration ClassConfiguration;
typedef struct _AssemblyConfiguration AssemblyConfiguration;
typedef struct _ImageProfiler ImageProfiler;
typedef struct _ClassProfiler ClassProfiler;
typedef struct _XmlParserState XmlParserState;

typedef uint8_t BOOL;

typedef enum {
	NotLoaded,
	Loaded,
	Failed,
} ProfilerLoadStatus;

struct _SearchableConfiguration {
	const char *name;
	SearchableConfiguration *next;
};

struct _Configuration {
	AssemblyConfiguration *firstAssembly;
};

struct _AssemblyConfiguration {
	const char *name;
	AssemblyConfiguration *next;

	ClassConfiguration *firstClass;
};

struct _ClassConfiguration {
	const char *name;
	ClassConfiguration *next;
	MethodConfiguration *firstMethod;
};

struct _MethodConfiguration {
	const char *name;
	MethodConfiguration *next;

	const char *parameters;
	const char *tracerFactoryName;
	const char *metricName;
	uint32_t tracerFlags;
};

struct _MonoProfiler {
	pthread_mutex_t lock;
	ProfilerLoadStatus status;
	ImageProfiler *images;
	MonoMethod *getTracerMethod;
	MonoMethod *finishTracerMethod;
	Configuration *configuration;
};

struct _ImageProfiler {
	pthread_mutex_t lock;
	ProfilerLoadStatus status;
	ImageProfiler *next;
	MonoImage *image;
	ClassProfiler *classes;
	uint32_t getTracerToken;
	uint32_t finishTracerToken;
	uint32_t assemblyNameToken;
	uint32_t int32TypeToken;
	uint32_t boolTypeToken;
	uint32_t objectTypeToken;
	uint32_t exceptionTypeToken;
	AssemblyConfiguration *configuration;
};

struct _ClassProfiler {
	MonoClass *class;
	ClassProfiler *next;
	uint32_t classNameToken;
	MethodConfiguration *methods;
};

struct _XmlParserState {
	Configuration *configuration;
	AssemblyConfiguration *assembly;
	ClassConfiguration *class;
	MethodConfiguration *method;

	const char *tracerFactory;
	uint8_t level;
	uint8_t transactionNamingPriority;
	const char *metric;
	const char *metricName;
};

static const unsigned char *dword_align(const unsigned char *ptr)
{
	return (const unsigned char *) (((uintptr_t) (ptr + 3)) & ~3);
}

void *findOrCreateObject(void *first, const char *name, size_t size)
{
	SearchableConfiguration **searchable = first;
	while (*searchable != NULL)
	{
		if (strcmp((*searchable)->name, name) == 0)
			return *searchable;

		searchable = &(*searchable)->next;
	}

	SearchableConfiguration *newSearchable = calloc(1, size);
	newSearchable->name = strdup(name);
	*searchable = newSearchable;

	return newSearchable;
}

void *findObject(void *first, const char *name)
{
	SearchableConfiguration *searchable = first;
	while (searchable != NULL)
	{
		if (strcmp(searchable->name, name) == 0)
			return searchable;

		searchable = searchable->next;
	}

	return NULL;
}

void image_loaded(MonoProfiler *profiler, MonoImage *image, int result)
{
	if (result != 0)
		return;

	const char *imageName = mono_image_get_name(image);

	AssemblyConfiguration *configurationAssembly = findObject(profiler->configuration->firstAssembly, imageName);
	if (configurationAssembly == NULL)
		return;

	ImageProfiler *imageProfiler = malloc(sizeof(ImageProfiler));
	pthread_mutex_init(&imageProfiler->lock, NULL);
	imageProfiler->image = image;
	imageProfiler->classes = NULL;
	imageProfiler->status = NotLoaded;
	imageProfiler->getTracerToken = 0;
	imageProfiler->finishTracerToken = 0;
	imageProfiler->configuration = configurationAssembly;

	pthread_mutex_lock(&profiler->lock);

	ProfilerLoadStatus status = profiler->status;
	if (status == Failed)
		imageProfiler->status = Failed;

	imageProfiler->next = profiler->images;
	profiler->images = imageProfiler;

	pthread_mutex_unlock(&profiler->lock);
}

char *getFullyQualifiedName(MonoClass *class)
{
	char *fullyQualifiedName = NULL;
	const char *className = mono_class_get_name(class);

	MonoClass *nestingClass = mono_class_get_nesting_type(class);
	if (nestingClass != NULL)
	{
		char *nestingClassName = getFullyQualifiedName(nestingClass);
		asprintf(&fullyQualifiedName, "%s+%s", nestingClassName, className);

		free(nestingClassName);
		nestingClassName = NULL;
	}
	else
	{
		const char *namespace = mono_class_get_namespace(class);
		size_t namespaceLength = namespace == NULL ? 0 : strlen(namespace);

		if (namespaceLength == 0)
			fullyQualifiedName = strdup(className);
		else
			asprintf(&fullyQualifiedName, "%s.%s", namespace, className);
	}

	return fullyQualifiedName;
}

void class_loaded(MonoProfiler *profiler, MonoClass *class, int result)
{
	if (result != 0)
		return;

	pthread_mutex_lock(&profiler->lock);

	ProfilerLoadStatus profilerStatus = profiler->status;
	ImageProfiler *imageProfiler = profiler->images;
	MonoMethod *getTracerMethod = profiler->getTracerMethod;
	MonoMethod *finishTracerMethod = profiler->finishTracerMethod;

	pthread_mutex_unlock(&profiler->lock);

	if (profilerStatus == Failed)
		return;

	MonoImage *image = mono_class_get_image(class);
	while (imageProfiler != NULL && imageProfiler->image != image)
		imageProfiler = imageProfiler->next;

	if (imageProfiler == NULL)
		return;

	char *qualifiedName = getFullyQualifiedName(class);

	ClassConfiguration *configurationClass = findObject(imageProfiler->configuration->firstClass, qualifiedName);

	free(qualifiedName);
	qualifiedName = NULL;

	if (configurationClass == NULL)
		return;

	pthread_mutex_lock(&imageProfiler->lock);

	uint32_t classNameToken;
	if (!mono_profiler_inject_user_string(image, configurationClass->name, &classNameToken))
		return;

	ClassProfiler *classProfiler = malloc(sizeof(ClassProfiler));
	classProfiler->class = class;
	classProfiler->classNameToken = classNameToken;
	classProfiler->methods = configurationClass->firstMethod;
	classProfiler->next = imageProfiler->classes;
	imageProfiler->classes = classProfiler;

	pthread_mutex_unlock(&imageProfiler->lock);
}

void writeInt8(unsigned char **destination, uint8_t value)
{
	*(uint8_t *) *destination = value;
	*destination += sizeof (uint8_t);
}

void writeInt16(unsigned char **destination, uint16_t value)
{
	*(uint16_t *) *destination = value;
	*destination += sizeof (uint16_t);
}

void writeInt32(unsigned char **destination, uint32_t value)
{
	*(uint32_t *) *destination = value;
	*destination += sizeof (uint32_t);
}

void writeInstruction(unsigned char **destination, unsigned char instruction)
{
	writeInt8(destination, instruction);
}

void writeInt8Instruction(unsigned char **destination, unsigned char instruction, uint8_t argument)
{
	writeInstruction(destination, instruction);
	writeInt8(destination, argument);
}

void writeInt16Instruction(unsigned char **destination, unsigned char instruction, uint16_t argument)
{
	writeInstruction(destination, instruction);
	writeInt16(destination, argument);
}


void writeInt32Instruction(unsigned char **destination, unsigned char instruction, uint32_t argument)
{
	writeInstruction(destination, instruction);
	writeInt32(destination, argument);
}

void writeStlocInstruction(unsigned char **destination, uint8_t localVariableIndex)
{
	if (localVariableIndex < 4)
		writeInstruction(destination, INSTRUCTION_STLOC_0 + localVariableIndex);
	else
		writeInt8Instruction(destination, INSTRUCTION_STLOC_S, localVariableIndex);
}

void writeLdlocInstruction(unsigned char **destination, uint8_t localVariableIndex)
{
	if (localVariableIndex < 4)
		writeInstruction(destination, INSTRUCTION_LDLOC_0 + localVariableIndex);
	else
		writeInt8Instruction(destination, INSTRUCTION_LDLOC_S, localVariableIndex);
}

uint8_t getBytesRequiredForLocInstruction(uint8_t localVariableIndex)
{
	if (localVariableIndex < 4)
		return 1;
	return 2;
}

typedef struct _PatchOffset PatchOffset;

struct _PatchOffset {
	uint32_t offset;
	uint32_t target;
	uint8_t size;
	uint32_t *targets;
	PatchOffset *next;
};

char *nameFromMonoType(MonoType *type)
{
	if (mono_type_is_void(type))
		return strdup("void");

	MonoClass *class = mono_class_from_mono_type(type);

	char *name = getFullyQualifiedName(class);
	if (mono_type_is_byref(type))
	{
		char *byrefName = NULL;
		asprintf(&byrefName, "%s&", name);

		free(name);
		name = byrefName;
	}

	return name;
}

uint32_t adjustFatOffset(const unsigned char *clausePosition, PatchOffset *patchOffsets, uint32_t prologueCodeBytes)
{
	uint32_t offset = *(uint32_t *) clausePosition;
	PatchOffset *patchOffset = patchOffsets;
	uint32_t patchesConsidered = 0;
	while (patchOffset != NULL && patchOffset->offset < offset)
	{
		patchesConsidered++;
		offset += patchOffset->size;
		patchOffset = patchOffset->next;
	}

	offset += prologueCodeBytes;

	return offset;
}

uint16_t adjustThinOffset(const unsigned char *clausePosition, PatchOffset *patchOffsets, uint32_t prologueCodeBytes)
{
	uint16_t offset = *(uint16_t *) clausePosition;
	PatchOffset *patchOffset = patchOffsets;
	uint32_t patchesConsidered = 0;
	uint32_t adjustment = 0;
	while (patchOffset != NULL && patchOffset->offset < offset)
	{
		patchesConsidered++;
		adjustment += patchOffset->size;
		patchOffset = patchOffset->next;
	}

	offset += prologueCodeBytes + adjustment;

	return offset;
}

void writeCompressedInteger(unsigned char **destination, uint32_t value)
{
	if (value < 0x80)
	{
		writeInt8(destination, value & 0x7F);
	}
	else if (value < 0x4000)
	{
		writeInt8(destination, ((value >> 8) & 0x3F) | 0x80);
		writeInt8(destination, value & 0xFF);
	}
	else
	{
		writeInt8(destination, ((value >> 24) & 0x1F) | 0xc0);
		writeInt8(destination, (value >> 16) & 0xFF);
		writeInt8(destination, (value >> 8) & 0xFF);
		writeInt8(destination, value & 0xFF);
	}
}

static MonoAssembly *agentCore = NULL;

static void jit_starting(MonoProfiler *profiler, MonoMethod *method)
{
	MonoClass *methodClass = mono_method_get_class(method);
	MonoImage *image = mono_class_get_image(methodClass);

	pthread_mutex_lock(&profiler->lock);

	ImageProfiler *imageProfiler = profiler->images;
	ProfilerLoadStatus profilerStatus = profiler->status;
	MonoMethod *getTracerMethod = profiler->getTracerMethod;
	MonoMethod *finishTracerMethod = profiler->finishTracerMethod;

	pthread_mutex_unlock(&profiler->lock);

	while (imageProfiler != NULL && imageProfiler->image != image)
		imageProfiler = imageProfiler->next;

	if (imageProfiler == NULL)
		return;

	pthread_mutex_lock(&imageProfiler->lock);

	ClassProfiler *classProfiler = imageProfiler->classes;
	ProfilerLoadStatus imageStatus = imageProfiler->status;

	pthread_mutex_unlock(&imageProfiler->lock);

	while (classProfiler != NULL && classProfiler->class != methodClass)
		classProfiler = classProfiler->next;

	if (classProfiler == NULL)
		return;

	const char *methodName = mono_method_get_name(method);
	MethodConfiguration *methodConfiguration = findObject(classProfiler->methods, methodName);

	if (methodConfiguration == NULL)
		return;

	if (profilerStatus == NotLoaded)
	{
		MonoImageOpenStatus status;
		MonoAssembly *additionsAssembly = mono_assembly_open("NewRelic.Additions.dll", &status);
		if (additionsAssembly != NULL && status == MONO_IMAGE_OK)
		{
			MonoImage *additionsImage = mono_assembly_get_image(additionsAssembly);
			if (additionsImage != NULL)
			{
				mono_image_addref(additionsImage);
				agentCore = mono_assembly_open("NewRelic.Agent.Core.dll", NULL);

				// "leak" the assembly to prevent it from being unloaded.
				mono_image_addref(mono_assembly_get_image(agentCore));

				MonoClass *agentShim = mono_class_from_name(additionsImage, "NewRelic.Additions", "MonoShim");
				if (agentShim != NULL)
				{
					getTracerMethod = mono_class_get_method_from_name(agentShim, "GetTracer", 9);
					finishTracerMethod = mono_class_get_method_from_name(agentShim, "FinishTracer", 3);
				}
			}
		}

		if (getTracerMethod == NULL || finishTracerMethod == NULL)
			return;

		pthread_mutex_lock(&profiler->lock);

		if (profiler->status == Loaded)
		{
			getTracerMethod = profiler->getTracerMethod;
			finishTracerMethod = profiler->finishTracerMethod;
			profilerStatus = Loaded;
		}
		else if (getTracerMethod != NULL && finishTracerMethod != NULL)
		{
			profiler->getTracerMethod = getTracerMethod;
			profiler->finishTracerMethod = finishTracerMethod;
			profiler->status = Loaded;
			profilerStatus = Loaded;
		}
		else
		{
			profiler->status = Failed;
			profilerStatus = Failed;
		}

		pthread_mutex_unlock(&profiler->lock);
	}

	if (profilerStatus != Loaded)
		return;

	if (imageStatus == NotLoaded)
	{
		pthread_mutex_lock(&imageProfiler->lock);

		while (imageProfiler->status == NotLoaded)
		{
			imageProfiler->status = Failed;

			if (!mono_profiler_inject_methodref(image, profiler->getTracerMethod, &imageProfiler->getTracerToken))
				break;

			if (!mono_profiler_inject_methodref(image, profiler->finishTracerMethod, &imageProfiler->finishTracerToken))
				break;

			if (!mono_profiler_inject_typeref(image, mono_get_object_class(), &imageProfiler->objectTypeToken))
				break;

			if (!mono_profiler_inject_typeref(image, mono_get_int32_class(), &imageProfiler->int32TypeToken))
				break;

			if (!mono_profiler_inject_typeref(image, mono_get_boolean_class(), &imageProfiler->boolTypeToken))
				break;

			if (!mono_profiler_inject_typeref(image, mono_get_exception_class(), &imageProfiler->exceptionTypeToken))
				break;

			if (!mono_profiler_inject_user_string(image, imageProfiler->configuration->name, &imageProfiler->assemblyNameToken))
				break;

			imageProfiler->status = Loaded;
		}

		imageStatus = imageProfiler->status;
		pthread_mutex_unlock(&imageProfiler->lock);
	}

	if (imageStatus != Loaded)
		return;

	MonoMethodSignature *signature = mono_method_signature(method);
	if (signature == NULL)
		return;

	// HACK: no static methods are currently being profiled. This assumption
	// allows for simpler code generation.
	if (!mono_signature_is_instance(signature))
		return;

	// HACK: none of the methods currently being profiled have more than four
	// parameters. This assumption allows the code to be simpler.
	uint32_t parameterCount = mono_signature_get_param_count(signature);
	if (parameterCount > MAX_ARGUMENTS)
		return;

	BOOL shouldIncludeParameter[MAX_ARGUMENTS];
	uint32_t parameterBoxType[MAX_ARGUMENTS];

	char *parameterTypes = NULL;
	void *iterator = NULL;
	int parameterIndex = 0;
	MonoType *parameterType = NULL;
	while ((parameterType = mono_signature_get_params(signature, &iterator)) != NULL)
	{
		int monoType = mono_type_get_type(parameterType);

		shouldIncludeParameter[parameterIndex] = monoType == MONO_TYPE_BOOLEAN ||
			monoType == MONO_TYPE_I4 || monoType == MONO_TYPE_STRING ||
			monoType == MONO_TYPE_CLASS || monoType == MONO_TYPE_OBJECT;

		parameterBoxType[parameterIndex] = monoType == MONO_TYPE_I4 ? imageProfiler->int32TypeToken :
			monoType == MONO_TYPE_BOOLEAN ? imageProfiler->boolTypeToken :
			0;

		if (parameterTypes == NULL)
		{
			parameterTypes = nameFromMonoType(parameterType);
		}
		else
		{
			char *parameterTypeName = nameFromMonoType(parameterType);
			char *parameterList = NULL;

			asprintf(&parameterList, "%s,%s", parameterTypes, parameterTypeName);

			free(parameterTypeName);
			parameterTypeName = NULL;

			free(parameterTypes);
			parameterTypes = parameterList;

			if (parameterTypes == NULL)
				return;
		}

		parameterIndex++;
	}

	if (parameterTypes == NULL)
	{
		parameterTypes = strdup("void");
		if (parameterTypes == NULL)
		{
			return;
		}
	}

	if (methodConfiguration->parameters != NULL && strcmp(methodConfiguration->parameters, parameterTypes) != 0)
	{
		free(parameterTypes);
		return;
	}

	MonoType *returnType = mono_signature_get_return_type(signature);

	BOOL isVoidMethod = mono_type_is_void(returnType);

	// HACK: Mono doesn't yet provide a good way to query for existing type tokens, so we'll just
	// inject an extra token.
	uint32_t returnTypeToken = 0;
	if (!isVoidMethod && !mono_profiler_inject_typeref(image, mono_class_from_mono_type(returnType), &returnTypeToken))
		return;

	char *returnTypeName = nameFromMonoType(returnType);

	char *signatureParameter = NULL;
	asprintf(&signatureParameter, "(%s)%s", parameterTypes, returnTypeName);

	free(returnTypeName);
	returnTypeName = NULL;

	free(parameterTypes);
	parameterTypes = NULL;

	if (signatureParameter == NULL)
		return;

	uint32_t signatureToken;
	BOOL addedSignatureToken = mono_profiler_inject_user_string(image, signatureParameter, &signatureToken);

	if (!addedSignatureToken)
		return;

	uint32_t tracerNameToken;
	if (!mono_profiler_inject_user_string(image, methodConfiguration->tracerFactoryName, &tracerNameToken))
		return;

	uint32_t methodNameToken;
	if (!mono_profiler_inject_user_string(image, methodName, &methodNameToken))
		return;

	uint32_t metricNameToken = 0;
	if (methodConfiguration->metricName != NULL && !mono_profiler_inject_user_string(image, methodConfiguration->metricName, &metricNameToken))
		return;

	const char *methodStart = mono_method_get_il_body(method);
	if (methodStart == NULL)
		return;

	unsigned char flags = *(const unsigned char *) methodStart;
	unsigned char format = flags & METHOD_HEADER_FORMAT_MASK;
	const unsigned char *codeStart = NULL;
	const char *epilogueStart = NULL;
	uint32_t bodySize = 0;
	uint32_t codeSize = 0;
	uint16_t fatFlags = METHOD_HEADER_FAT_FORMAT | METHOD_HEADER_MORE_SECTS | (0x30 << 8);
	uint16_t maxStack = 0;
	uint32_t localVariableSignatureToken = 0;
	uint32_t epilogueSize = 0;

	switch (format)
	{
	case METHOD_HEADER_TINY_FORMAT:
		codeSize = (flags >> 2);
		maxStack = 8;
		bodySize = codeSize + 1;
		codeStart = methodStart + 1;
		epilogueStart = methodStart + bodySize;
		break;
	case METHOD_HEADER_FAT_FORMAT:
		{
			const char *position = methodStart;

			fatFlags = *(const uint16_t *) position;
			position += 2;

			maxStack = *(const uint16_t *) position;
			position += 2;

			codeSize = *(const uint32_t *) position;
			position += 4;

			localVariableSignatureToken = *(const uint32_t *) position;
			position += 4;

			codeStart = position;
			if (fatFlags & METHOD_HEADER_MORE_SECTS)
			{
				position += codeSize;
				unsigned char sectionDataFlags = 0;

				epilogueStart = dword_align(position);

				do
				{
					position = dword_align(position);
					sectionDataFlags = *position;
					position++;

					if (sectionDataFlags & METHOD_HEADER_SECTION_FAT_FORMAT)
						position += ((position[2] << 16) | (position[1] << 8) | position[0]) - 1;
					else
						position += position[0] - 1;
				} while (sectionDataFlags & METHOD_HEADER_SECTION_MORE_SECTS);

				epilogueSize = position - epilogueStart;
			}

			bodySize = position - methodStart;

			break;
		}
	default:
		return;
	}

	uint32_t originalBlobSize = 0;
	uint32_t localsCount = 0;
	const char *localsBlob = NULL;
	const char *localsPosition = NULL;
	if (localVariableSignatureToken != 0)
	{
		const MonoTableInfo *standaloneSignatureTable = mono_image_get_table_info(image, MONO_TABLE_STANDALONESIG);
		uint32_t standaloneSignatureColumns[MONO_STAND_ALONE_SIGNATURE_SIZE];
		mono_metadata_decode_row(standaloneSignatureTable, (localVariableSignatureToken & 0xffffff) - 1, standaloneSignatureColumns, 1);
		localsBlob = mono_metadata_blob_heap(image, standaloneSignatureColumns[MONO_STAND_ALONE_SIGNATURE]);
		localsPosition = localsBlob;
		originalBlobSize = mono_metadata_decode_blob_size (localsPosition, &localsPosition);

		// skip the 0x7 signature
		localsPosition++;

		localsCount = mono_metadata_decode_value (localsPosition, &localsPosition);
	}

	if (localsCount > 252)
		return;

	uint8_t tracerLocalIndex = localsCount;
	uint8_t exceptionLocalIndex = localsCount + 1;
	uint8_t returnValueLocalIndex = localsCount + 2;

	localsCount += isVoidMethod ? 2 : 3;

	uint32_t blobSize = originalBlobSize + (isVoidMethod ? 2 : 3);

	uint32_t encodedReturnTypeToken = ((0x00FFFFFF & returnTypeToken) << 2) | 0x1;
	int monoReturnType = mono_type_get_type(returnType);
	if (monoReturnType == MONO_TYPE_CLASS)
	{
		if (encodedReturnTypeToken > 0x3FFF)
			blobSize += 4;
		else if (encodedReturnTypeToken > 0x7F)
			blobSize += 2;
		else
			blobSize++;
	}

	uint32_t encodedExceptionTypeToken = ((0x00FFFFFF & imageProfiler->exceptionTypeToken) << 2) | 0x1;
	if (encodedExceptionTypeToken > 0x3FFF)
		blobSize += 4;
	else if (encodedExceptionTypeToken > 0x7F)
		blobSize += 2;
	else
		blobSize++;

	if (localsCount > 0x7F && localsCount < 0x83)
		blobSize++;

	uint32_t fullBlobSize = blobSize;
	if (blobSize < 0x80)
		fullBlobSize++;
	else if (blobSize < 0x40FF)
		fullBlobSize += 2;
	else
		fullBlobSize += 4;

	unsigned char *newLocalsBlob = malloc(fullBlobSize);
	unsigned char *newLocalsPosition = newLocalsBlob;

	writeCompressedInteger(&newLocalsPosition, blobSize);
	writeInt8(&newLocalsPosition, 0x07);
	writeCompressedInteger(&newLocalsPosition, localsCount);

	if (localsPosition != NULL)
	{
		ptrdiff_t originalBytes = originalBlobSize - (localsPosition - localsBlob) + 1;
		memcpy(newLocalsPosition, localsPosition, originalBytes);
		newLocalsPosition += originalBytes;
	}

	writeCompressedInteger(&newLocalsPosition, MONO_TYPE_OBJECT);
	writeCompressedInteger(&newLocalsPosition, MONO_TYPE_CLASS);
	writeCompressedInteger(&newLocalsPosition, encodedExceptionTypeToken);
	if (!isVoidMethod)
	{
		writeCompressedInteger(&newLocalsPosition, monoReturnType);
		if (monoReturnType == MONO_TYPE_CLASS)
			writeCompressedInteger(&newLocalsPosition, encodedReturnTypeToken);
	}

	if (!mono_profiler_inject_locals(image, newLocalsBlob, &localVariableSignatureToken))
	{
		free(newLocalsBlob);
		return;
	}

	


	PatchOffset *reversedPatchOffsets = NULL;

	for (uint32_t codeOffset = 0; codeOffset < codeSize; codeOffset++)
	{
		switch (codeStart[codeOffset])
		{
		case 0x2A:
		{
			PatchOffset *offset = malloc(sizeof (PatchOffset));
			offset->offset = codeOffset;
			offset->next = reversedPatchOffsets;
			offset->size = 0;
			offset->target = 0;
			offset->targets = NULL;
			reversedPatchOffsets = offset;
			break;
		}
		case 0x2B:
		case 0x2C:
		case 0x2D:
		case 0x2E:
		case 0x2F:
		case 0x30:
		case 0x31:
		case 0x32:
		case 0x33:
		case 0x34:
		case 0x35:
		case 0x36:
		case 0x37:
		case 0xDE:
		{
			PatchOffset *offset = malloc(sizeof (PatchOffset));
			offset->offset = codeOffset;
			offset->next = reversedPatchOffsets;
			offset->size = 3;
			offset->target = 0;
			offset->targets = NULL;
			reversedPatchOffsets = offset;

			codeOffset++;
			break;
		}
		case 0x0E:
		case 0x0F:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x1F:
			codeOffset++;
			break;
		case 0x38:
		case 0x39:
		case 0x3A:
		case 0x3B:
		case 0x3C:
		case 0x3D:
		case 0x3E:
		case 0x3F:
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0xDD:
		{
			PatchOffset *offset = malloc(sizeof (PatchOffset));
			offset->offset = codeOffset;
			offset->size = 0;
			offset->next = reversedPatchOffsets;
			offset->target = 0;
			offset->targets = NULL;
			reversedPatchOffsets = offset;

			codeOffset += 4;
			break;
		}
		case 0x20:
		case 0x22:
		case 0x27:
		case 0x28:
		case 0x29:
		case 0x6F:
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x79:
		case 0x7B:
		case 0x7C:
		case 0x7D:
		case 0x7E:
		case 0x7F:
		case 0x80:
		case 0x81:
		case 0x8C:
		case 0x8D:
		case 0x8F:
		case 0xA3:
		case 0xA5:
		case 0xC2:
		case 0xC6:
		case 0xD0:
			codeOffset += 4;
			break;
		case 0x21:
		case 0x23:
			codeOffset += 8;
			break;
		case 0x45:
		{
			PatchOffset *offset = malloc(sizeof (PatchOffset));
			offset->offset = codeOffset;
			offset->next = reversedPatchOffsets;
			offset->target = 0;
			offset->size = 0;
			offset->targets = NULL;
			reversedPatchOffsets = offset;

			codeOffset++;
			codeOffset += 4 + (*(uint32_t *) &codeStart[codeOffset]);
			break;
		}
		case 0xFE:
			// TODO: 0xFE14 is the tail call marker. We should remove these.
			codeOffset++;
			switch (codeStart[codeOffset])
			{
				case 0x12:
				case 0x19:
					codeOffset++;
					break;
				case 0x09:
				case 0x0A:
				case 0x0B:
				case 0x0C:
				case 0x0D:
				case 0x0E:
					codeOffset += 2;
					break;
				case 0x06:
				case 0x07:
				case 0x15:
				case 0x16:
				case 0x1C:
					codeOffset += 4;
					break;
			}
			break;
		}
	}

	uint8_t tracerBytes = getBytesRequiredForLocInstruction(tracerLocalIndex);
	uint8_t exceptionBytes = getBytesRequiredForLocInstruction(exceptionLocalIndex);
	uint8_t returnValueBytes = getBytesRequiredForLocInstruction(returnValueLocalIndex);

	uint32_t prologueCodeBytes = 38 + tracerBytes;

	if (metricNameToken != 0)
		prologueCodeBytes += sizeof(uint32_t);

	if (parameterCount == 0)
	{
		prologueCodeBytes++;
	}
	else
	{
		prologueCodeBytes += 6 + ((3 + tracerBytes) * parameterCount) + 2 * tracerBytes;
		if (parameterCount == 4 && shouldIncludeParameter[3])
			prologueCodeBytes++;
	}

	for (parameterIndex = 0; parameterIndex < parameterCount; parameterIndex++)
	{
		if (parameterBoxType[parameterIndex] != 0)
			prologueCodeBytes += 5;
	}

	uint32_t patchInstructionBytes = 0;
	uint32_t patchCount = 0;

	// Assign sizes and targets to patched return instructions
	PatchOffset *patchOffset = reversedPatchOffsets;
	while (patchOffset != NULL)
	{
		patchCount++;

		if (codeStart[patchOffset->offset] == 0x2A)
		{
			patchOffset->target = ((codeSize - reversedPatchOffsets->offset - 1) + patchInstructionBytes);
			patchOffset->size = (reversedPatchOffsets->target < 128) ? 1 : 4;
		}

		patchInstructionBytes += reversedPatchOffsets->size;
		patchOffset = patchOffset->next;
	}

	// Reverse the list and update targets
	PatchOffset *patchOffsets = NULL;
	while (reversedPatchOffsets != NULL)
	{
		uint32_t patchesConsidered = 0;

		if ((codeStart[reversedPatchOffsets->offset] >= 0x2B && codeStart[reversedPatchOffsets->offset] <= 0x37) ||
			codeStart[reversedPatchOffsets->offset] == 0xDE)
		{
			int8_t target = *(int8_t *) (codeStart + reversedPatchOffsets->offset + 1);
			uint32_t absoluteTarget = reversedPatchOffsets->offset + 2 + target;
			int32_t targetDisplacement = 0;
			if (target > 0)
			{
				PatchOffset *branchOffset = patchOffsets;
				while (branchOffset != NULL && branchOffset->offset < absoluteTarget)
				{
					targetDisplacement += branchOffset->size;
					branchOffset = branchOffset->next;
					patchesConsidered++;
				}
			}
			else if (target < 0)
			{
				PatchOffset *branchOffset = reversedPatchOffsets->next;
				while (branchOffset != NULL && branchOffset->offset <= absoluteTarget)
				{
					targetDisplacement -= branchOffset->size;
					branchOffset = branchOffset->next;
					patchesConsidered++;
				}
			}
			reversedPatchOffsets->target = target + targetDisplacement;
		}
		else if ((codeStart[reversedPatchOffsets->offset] >= 0x38 && codeStart[reversedPatchOffsets->offset] <= 0x44) ||
			codeStart[reversedPatchOffsets->offset] == 0xDD)
		{
			int32_t target = *(int32_t *) (codeStart + reversedPatchOffsets->offset + 1);
			uint32_t absoluteTarget = reversedPatchOffsets->offset + 5 + target;
			int32_t targetDisplacement = 0;
			if (target > 0)
			{
				PatchOffset *branchOffset = patchOffsets;
				while (branchOffset != NULL && branchOffset->offset < absoluteTarget)
				{
					targetDisplacement += branchOffset->size;
					branchOffset = branchOffset->next;
					patchesConsidered++;
				}
			}
			else if (target < 0)
			{
				PatchOffset *branchOffset = reversedPatchOffsets->next;
				while (branchOffset != NULL && branchOffset->offset >= absoluteTarget)
				{
					targetDisplacement -= branchOffset->size;
					branchOffset = branchOffset->next;
					patchesConsidered++;
				}
			}
			reversedPatchOffsets->target = target + targetDisplacement;
		}
		else if (codeStart[reversedPatchOffsets->offset] == 0x45)
		{
			uint32_t targetCount = *(uint32_t *) (codeStart + reversedPatchOffsets->offset + 1);
			int32_t *originalTargets = (int32_t *) (codeStart + reversedPatchOffsets->offset + 1 + sizeof(uint32_t));
			uint32_t afterInstructionOffset = reversedPatchOffsets->offset + 1 + sizeof(uint32_t) + (sizeof(int32_t) * targetCount);

			reversedPatchOffsets->targets = malloc(targetCount * sizeof(int32_t));

			for (uint32_t targetIndex = 0; targetIndex < targetCount; targetIndex++)
			{
				patchesConsidered = 0;
				int32_t target = originalTargets[targetIndex];
				uint32_t absoluteTarget = afterInstructionOffset + target;
				int32_t targetDisplacement = 0;
				if (target > 0)
				{
					PatchOffset *branchOffset = patchOffsets;
					while (branchOffset != NULL && branchOffset->offset < absoluteTarget)
					{
						targetDisplacement += branchOffset->size;
						branchOffset = branchOffset->next;
						patchesConsidered++;
					}
				}
				else if (target < 0)
				{
					PatchOffset *branchOffset = reversedPatchOffsets->next;
					while (branchOffset != NULL && branchOffset->offset <= absoluteTarget)
					{
						targetDisplacement -= branchOffset->size;
						branchOffset = branchOffset->next;
						patchesConsidered++;
					}
				}
				reversedPatchOffsets->targets[targetIndex] = target + targetDisplacement;
			}
		}

		PatchOffset *temp = reversedPatchOffsets;
		reversedPatchOffsets = reversedPatchOffsets->next;

		temp->next = patchOffsets;
		patchOffsets = temp;
	}

	uint32_t epilogueCodeBytes = 3;
	uint32_t catchBlockBytes = 10 + (tracerBytes * 2) + (exceptionBytes * 2);
	uint32_t returnBytes = 9 + (tracerBytes * 2);
	if (isVoidMethod)
	{
		returnBytes++;
	}
	else
	{
		epilogueCodeBytes += returnValueBytes;
		returnBytes += 2 * returnValueBytes;
	}

	const uint32_t headerBytes = 12;
	const uint32_t exceptionHandlerBytes = 31;
	uint32_t extraCodeBytes = prologueCodeBytes + epilogueCodeBytes + catchBlockBytes + returnBytes + patchInstructionBytes;

	unsigned char *section = malloc(headerBytes + codeSize + extraCodeBytes + 3 + (epilogueSize * 2) + exceptionHandlerBytes);
	unsigned char *writePosition = section;

	writeInt16(&writePosition, fatFlags | METHOD_HEADER_MORE_SECTS);
	writeInt16(&writePosition, maxStack > 20 ? maxStack : 20);

	uint32_t *codeSizeLocation = (uint32_t *) writePosition;

	writeInt32(&writePosition, codeSize + extraCodeBytes);
	writeInt32(&writePosition, localVariableSignatureToken);

	unsigned char *replacementCodeStart = writePosition;

	writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, tracerNameToken);
	writeInt32Instruction(&writePosition, INSTRUCTION_LDC_I4, methodConfiguration->tracerFlags);

	if (metricNameToken != 0)
		writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, metricNameToken);
	else
		writeInstruction(&writePosition, INSTRUCTION_LDNULL);

	writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, imageProfiler->assemblyNameToken);
	writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, classProfiler->classNameToken);
	writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, methodNameToken);
	writeInt32Instruction(&writePosition, INSTRUCTION_LDSTR, signatureToken);

	writeInstruction(&writePosition, INSTRUCTION_LDARG_0);

	if (parameterCount == 0)
	{
		writeInstruction(&writePosition, INSTRUCTION_LDNULL);
	}
	else
	{
		writeInstruction(&writePosition, INSTRUCTION_LDC_I4_0 + parameterCount);
		writeInt32Instruction(&writePosition, INSTRUCTION_NEWARR, imageProfiler->objectTypeToken);

		for (uint8_t parameterIndex = 0; parameterIndex < parameterCount; parameterIndex++)
		{
			uint8_t argumentIndex = parameterIndex + 1;
		
			writeInstruction(&writePosition, INSTRUCTION_DUP);
			writeInstruction(&writePosition, INSTRUCTION_LDC_I4_0 + parameterIndex);
		
			if (!shouldIncludeParameter[parameterIndex])
				writeInstruction(&writePosition, INSTRUCTION_LDNULL);
			else if (argumentIndex < 4)
				writeInstruction(&writePosition, INSTRUCTION_LDARG_0 + argumentIndex);
			else
				writeInt8Instruction(&writePosition, INSTRUCTION_LDARG_S, argumentIndex);
		
			if (parameterBoxType[parameterIndex] != 0)
				writeInt32Instruction(&writePosition, INSTRUCTION_BOX, parameterBoxType[parameterIndex]);
		
			writeInstruction(&writePosition, INSTRUCTION_STELEM_REF);
		}
	}

	writeInt32Instruction(&writePosition, INSTRUCTION_CALL, imageProfiler->getTracerToken);
	writeStlocInstruction(&writePosition, tracerLocalIndex);

	writeInstruction(&writePosition, INSTRUCTION_NOP);

	unsigned char *prologueEnd = writePosition;

	uint32_t codeOffset = 0;
	patchOffset = patchOffsets;
	while (patchOffset != NULL)
	{
		uint32_t copyCount = patchOffset->offset - codeOffset;
		memcpy(writePosition, codeStart + codeOffset, copyCount);

		writePosition += copyCount;

		uint8_t instruction = codeStart[patchOffset->offset];

		if (instruction == INSTRUCTION_RET)
		{
			if (patchOffset->size == 1)
				writeInt8Instruction(&writePosition, INSTRUCTION_BR_S, (int8_t) patchOffset->target);
			else
				writeInt32Instruction(&writePosition, INSTRUCTION_BR, (int32_t) patchOffset->target);

			codeOffset = patchOffset->offset + 1;
		}
		else if ((instruction >= 0x2B && instruction <= 0x37) || instruction == 0xDE)
		{
			uint8_t longInstruction = instruction == 0xDE ?
				0xdd :
				(instruction - 0x2B + 0x38);

			writeInt32Instruction(&writePosition, longInstruction, patchOffset->target);
			codeOffset = patchOffset->offset + 2;
		}
		else if ((instruction >= 0x38 && instruction <= 0x44) || instruction == 0xDD)
		{
			writeInt32Instruction(&writePosition, instruction, patchOffset->target);
			codeOffset = patchOffset->offset + 5;
		}
		else
		{
			uint32_t targetCount = *(uint32_t *) (codeStart + patchOffset->offset + 1);
			writeInt32Instruction(&writePosition, instruction, targetCount);
			for (uint32_t targetIndex = 0; targetIndex < targetCount; targetIndex++)
				writeInt32(&writePosition, *(uint32_t *) (patchOffset->targets + targetIndex));
			codeOffset = patchOffset->offset + 5 + (targetCount * sizeof(int32_t));
		}

		patchOffset = patchOffset->next;
	}

	memcpy(writePosition, codeStart + codeOffset, codeSize - codeOffset);

	writePosition += codeSize - codeOffset;

	writeInstruction(&writePosition, INSTRUCTION_NOP);

	if (!isVoidMethod)
		writeStlocInstruction(&writePosition, returnValueLocalIndex);

	writeInt8Instruction(&writePosition, INSTRUCTION_LEAVE_S, 10 + (2 * (exceptionBytes + tracerBytes)));

	unsigned char *codeEnd = writePosition;

	// Exception handler
	writeStlocInstruction(&writePosition, exceptionLocalIndex);
	writeLdlocInstruction(&writePosition, tracerLocalIndex);
	writeInt8Instruction(&writePosition, INSTRUCTION_BRFALSE_S, 6 + tracerBytes + exceptionBytes);
	writeLdlocInstruction(&writePosition, tracerLocalIndex);
	writeInstruction(&writePosition, INSTRUCTION_LDNULL);
	writeLdlocInstruction(&writePosition, exceptionLocalIndex);
	writeInt32Instruction(&writePosition, INSTRUCTION_CALL, imageProfiler->finishTracerToken);
	writeInt16(&writePosition, INSTRUCTION_RETHROW);

	unsigned char *exceptionHandlerEnd = writePosition;

	writeLdlocInstruction(&writePosition, tracerLocalIndex);
	writeInt8Instruction(&writePosition, INSTRUCTION_BRFALSE_S, 6 + tracerBytes + returnValueBytes);
	writeLdlocInstruction(&writePosition, tracerLocalIndex);

	if (!isVoidMethod && monoReturnType == MONO_TYPE_CLASS)
		writeLdlocInstruction(&writePosition, returnValueLocalIndex);
	else
		writeInstruction(&writePosition, INSTRUCTION_LDNULL);

	writeInstruction(&writePosition, INSTRUCTION_LDNULL);
	writeInt32Instruction(&writePosition, INSTRUCTION_CALL, imageProfiler->finishTracerToken);

	if (!isVoidMethod)
		writeLdlocInstruction(&writePosition, returnValueLocalIndex);

	writeInstruction(&writePosition, INSTRUCTION_RET);

	unsigned char *methodEnd = writePosition;
	*codeSizeLocation = methodEnd - replacementCodeStart;

	writePosition = (char *) dword_align(writePosition);

	uint8_t exceptionHandlerFlags = 0x41;
	// if (epilogueSize != 0)
	// 	exceptionHandlerFlags |= METHOD_HEADER_SECTION_MORE_SECTS;

	writePosition = (unsigned char *) dword_align(writePosition);
	// Kind
	writeInt8(&writePosition, exceptionHandlerFlags);

	// Data Size (3 bytes, little endian)

	uint16_t *sectionLengthPosition = (uint16_t *) writePosition;
	writeInt16(&writePosition, 28);
	writeInt8(&writePosition, 0);

	// writePosition = (unsigned char *) dword_align(writePosition);
	// memcpy(writePosition, epilogueStart, epilogueSize);

	if (epilogueSize != 0)
	{
		const unsigned char *epiloguePosition = epilogueStart;

		unsigned char sectionDataFlags = 0;
		do
		{
			epiloguePosition = (unsigned char *) dword_align(epiloguePosition);
			sectionDataFlags = *epiloguePosition;
			epiloguePosition++;

			uint32_t sectionLength;
			uint8_t isFat = sectionDataFlags & METHOD_HEADER_SECTION_FAT_FORMAT;

			if (isFat)
				sectionLength = ((epiloguePosition[2] << 16) | (epiloguePosition[1] << 8) | epiloguePosition[0]);
			else
				sectionLength = epiloguePosition[0];

			if (sectionDataFlags & METHOD_HEADER_SECTION_EHTABLE)
			{
				uint32_t clauseCount = isFat ? (sectionLength / 24) : (sectionLength / 12);
				(*sectionLengthPosition) += clauseCount * 24;

				const unsigned char *clausePosition = epiloguePosition + 3;
				for (uint32_t clause = 0; clause < clauseCount; clause++)
				{
					if (isFat)
					{
						uint32_t flags = *(uint32_t *) clausePosition;
						clausePosition += 4;
						writeInt32(&writePosition, flags);

						// adjust try offset
						writeInt32(&writePosition, adjustFatOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						clausePosition += 4;
						writeInt32(&writePosition, *(uint32_t *) clausePosition);
						clausePosition += 4;

						// adjust handler offset
						writeInt32(&writePosition, adjustFatOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						clausePosition += 4;
						writeInt32(&writePosition, *(uint32_t *) clausePosition);
						clausePosition += 4;

						// adjust filter block offset
						if (flags & 0x1)
							writeInt32(&writePosition, adjustFatOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						else
							writeInt32(&writePosition, *(uint32_t *) clausePosition);

						clausePosition += 4;
					}
					else
					{
						uint16_t flags = *(uint16_t *) clausePosition;
						clausePosition += 2;
						writeInt32(&writePosition, flags);

						// adjust try offset
						writeInt32(&writePosition, adjustThinOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						clausePosition += 2;
						writeInt32(&writePosition, *clausePosition);
						clausePosition++;

						// adjust handler offset
						writeInt32(&writePosition, adjustThinOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						clausePosition += 2;
						writeInt32(&writePosition, *clausePosition);
						clausePosition++;

						// adjust filter block offset
						if (flags & 0x1)
							writeInt32(&writePosition, adjustFatOffset(clausePosition, patchOffsets, prologueEnd - replacementCodeStart));
						else
							writeInt32(&writePosition, *(uint32_t *) clausePosition);

						clausePosition += 4;
					}
				}
			}

			epiloguePosition += sectionLength;
		} while ((sectionDataFlags & METHOD_HEADER_SECTION_MORE_SECTS) != 0);
	}

	writeInt32(&writePosition, 0x0000);
	writeInt32(&writePosition, prologueEnd - replacementCodeStart);
	writeInt32(&writePosition, codeEnd - prologueEnd);
	writeInt32(&writePosition, codeEnd - replacementCodeStart);
	writeInt32(&writePosition, exceptionHandlerEnd - codeEnd);
	writeInt32(&writePosition, imageProfiler->exceptionTypeToken);

	while (patchOffsets != NULL)
	{
		PatchOffset *temp = patchOffsets;
		patchOffsets = patchOffsets->next;
		if (temp->targets != NULL)
		{
			free(temp->targets);
			temp->targets = NULL;
		}
		free(temp);
		temp = NULL;
	}

	if (!mono_profiler_replace_method_body(method, section))
		fprintf(stderr, "failed?!\n");
}

static void shutdown (MonoProfiler *prof)
{
}

const char *xml_attribute_value(const XML_Char **attrs, const char *name)
{
	while (*attrs != NULL && *(attrs + 1) != NULL)
	{
		if (strcmp(*attrs, name) == 0)
			return *(attrs + 1);

		attrs += 2;
	}

	return NULL;
}

void handle_start_element(void *userData, const XML_Char *name, const XML_Char **attrs)
{
	assert(attrs);
	XmlParserState *parserState = userData;

	if (strcmp(name, "exactMethodMatcher") == 0)
	{
		const char *methodName = xml_attribute_value(attrs, "methodName");
		if (methodName == NULL || parserState->tracerFactory == NULL)
			return;

		parserState->method = findOrCreateObject(&parserState->class->firstMethod, methodName, sizeof (MethodConfiguration));

		const char *parameters = xml_attribute_value(attrs, "parameters");
		if (parameters != NULL)
			parserState->method->parameters = strdup(parameters);

		parserState->method->tracerFactoryName = parserState->tracerFactory;

		parserState->method->tracerFlags = 0x00002400 | (parserState->level << 16) | (parserState->transactionNamingPriority << 24);

		if (parserState->metricName == NULL || strcmp("instance", parserState->metricName) != 0)
		{
			parserState->method->metricName = parserState->metricName;
			parserState->method->tracerFlags |= 0x00008000;
		}

		if (parserState->metric == NULL || strcmp("none", parserState->metric) != 0)
			parserState->method->tracerFlags |= 0x00001000;
	}
	else if (strcmp(name, "match") == 0)
	{
		parserState->method = NULL;

		const char *assemblyName = xml_attribute_value(attrs, "assemblyName");
		if (assemblyName == NULL)
			return;

		const char *className = xml_attribute_value(attrs, "className");
		if (className == NULL)
			return;

		parserState->assembly = findOrCreateObject(
			&parserState->configuration->firstAssembly,
			assemblyName,
			sizeof (AssemblyConfiguration));

		parserState->class = findOrCreateObject(
			&parserState->assembly->firstClass,
			className,
			sizeof (ClassConfiguration));
	}
	else if (strcmp(name, "tracerFactory") == 0)
	{
		const char *tracerFactory = xml_attribute_value(attrs, "name");
		const char *metric = xml_attribute_value(attrs, "metric");
		const char *transactionNamingPriority = xml_attribute_value(attrs, "transactionNamingPriority");
		const char *level = xml_attribute_value(attrs, "level");

		parserState->tracerFactory = tracerFactory != NULL ? strdup(tracerFactory) : NULL;
		parserState->metric = metric != NULL ? strdup(metric) : NULL;
		parserState->transactionNamingPriority = transactionNamingPriority != NULL ? atoi(transactionNamingPriority) : 0;
		parserState->level = level != NULL ? atoi(level) : 0;

		parserState->assembly = NULL;
		parserState->class = NULL;
		parserState->method = NULL;
	}
}

Configuration *parse_configuration()
{
	XML_Parser parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(parser, handle_start_element, NULL);

	Configuration *configuration = calloc(1, sizeof(Configuration));
	XmlParserState parserState = { configuration, NULL, NULL, NULL };
	XML_SetUserData(parser, &parserState);

	FILE *xmlSource = fopen("CoreInstrumentation.xml", "r");
	assert(xmlSource != NULL);

	while (!feof(xmlSource))
	{
		char buffer[4096];
		size_t length = fread(buffer, 1, 4096, xmlSource);
		if (!XML_Parse(parser, buffer, length, feof(xmlSource)))
			assert(0);
	}

	fclose(xmlSource);
	XML_ParserFree(parser);

	return configuration;
}

void appdomain_loaded(MonoProfiler *profiler, MonoDomain *domain, int result)
{
	pthread_mutex_lock(&profiler->lock);

	if (profiler->status == Loaded)
	{
		mono_assembly_open("NewRelic.Additions.dll", NULL);
		mono_assembly_open("NewRelic.Agent.Core.dll", NULL);
	}

	pthread_mutex_unlock(&profiler->lock);
}

void image_unloading(MonoProfiler *profiler, MonoImage *image)
{
	pthread_mutex_lock(&profiler->lock);
	ImageProfiler *unloadingImage = profiler->images;
	pthread_mutex_unlock(&profiler->lock);

	while (unloadingImage != NULL && unloadingImage->image != image)
		unloadingImage = unloadingImage->next;

	if (unloadingImage != NULL)
	{
		pthread_mutex_lock(&unloadingImage->lock);
		unloadingImage->status = NotLoaded;
		unloadingImage->getTracerToken = 0;
		unloadingImage->finishTracerToken = 0;
		unloadingImage->assemblyNameToken = 0;
		unloadingImage->int32TypeToken = 0;
		unloadingImage->boolTypeToken = 0;
		unloadingImage->objectTypeToken = 0;
		unloadingImage->exceptionTypeToken = 0;
		ClassProfiler *classProfiler = unloadingImage->classes;
		unloadingImage->classes = NULL;
		pthread_mutex_unlock(&unloadingImage->lock);

		while (classProfiler != NULL)
		{
			ClassProfiler *temp = classProfiler;
			classProfiler = classProfiler->next;
			free(temp);
		}
	}

	if (strcmp("NewRelic.Additions", mono_image_get_name(image)) == 0)
	{
		pthread_mutex_lock(&profiler->lock);
		profiler->status = NotLoaded;
		profiler->getTracerMethod = NULL;
		profiler->finishTracerMethod = NULL;
		ImageProfiler *imageProfiler = profiler->images;
		profiler->images = NULL;
		pthread_mutex_unlock(&profiler->lock);

		while (imageProfiler != NULL)
		{
			pthread_mutex_lock(&imageProfiler->lock);
			imageProfiler->status = Failed;
			ClassProfiler *class = imageProfiler->classes;
			pthread_mutex_unlock(&imageProfiler->lock);
			ImageProfiler *tempImage = imageProfiler;
			imageProfiler = imageProfiler->next;
			free(tempImage);

			while (class != NULL)
			{
				ClassProfiler *temp = class;
				class = class->next;
				free(temp);
			}
		}
	}
}

MonoAssembly *assemblySearch(MonoAssemblyName *name, void *nothing)
{
	if (agentCore != NULL && strcmp("NewRelic.Agent.Core", mono_assembly_name_get_name(name)) == 0)
		return agentCore;
	return NULL;
}

void mono_profiler_startup (const char *desc)
{
	MonoProfiler *profiler = malloc(sizeof(MonoProfiler));
	pthread_mutex_init(&profiler->lock, NULL);
	profiler->images = NULL;
	profiler->status = NotLoaded;

	profiler->configuration = parse_configuration();

mono_install_assembly_search_hook(assemblySearch, NULL);
	mono_profiler_install(profiler, shutdown);
	mono_profiler_install_module(NULL, image_loaded, image_unloading, NULL);
	mono_profiler_install_class(NULL, class_loaded, NULL, NULL);
	mono_profiler_install_jit_compile(jit_starting, NULL);
	mono_profiler_install_appdomain(NULL, appdomain_loaded, NULL, NULL);

	mono_profiler_set_events (MONO_PROFILE_APPDOMAIN_EVENTS | MONO_PROFILE_MODULE_EVENTS | MONO_PROFILE_CLASS_EVENTS | MONO_PROFILE_JIT_COMPILATION);
}
