// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/KeyPair.proto

#include "skissm/KeyPair.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace skissm {
constexpr KeyPair::KeyPair(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : public_key_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , private_key_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string){}
struct KeyPairDefaultTypeInternal {
  constexpr KeyPairDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~KeyPairDefaultTypeInternal() {}
  union {
    KeyPair _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT KeyPairDefaultTypeInternal _KeyPair_default_instance_;
}  // namespace skissm
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fKeyPair_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fKeyPair_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fKeyPair_2eproto = nullptr;

const uint32_t TableStruct_skissm_2fKeyPair_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::skissm::KeyPair, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::skissm::KeyPair, public_key_),
  PROTOBUF_FIELD_OFFSET(::skissm::KeyPair, private_key_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::skissm::KeyPair)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::skissm::_KeyPair_default_instance_),
};

const char descriptor_table_protodef_skissm_2fKeyPair_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\024skissm/KeyPair.proto\022\006skissm\"2\n\007KeyPai"
  "r\022\022\n\npublic_key\030\001 \001(\014\022\023\n\013private_key\030\002 \001"
  "(\014B(\n\030org.e2eelab.skissm.protoB\014KeyPairP"
  "rotob\006proto3"
  ;
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fKeyPair_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fKeyPair_2eproto = {
  false, false, 132, descriptor_table_protodef_skissm_2fKeyPair_2eproto, "skissm/KeyPair.proto", 
  &descriptor_table_skissm_2fKeyPair_2eproto_once, nullptr, 0, 1,
  schemas, file_default_instances, TableStruct_skissm_2fKeyPair_2eproto::offsets,
  file_level_metadata_skissm_2fKeyPair_2eproto, file_level_enum_descriptors_skissm_2fKeyPair_2eproto, file_level_service_descriptors_skissm_2fKeyPair_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fKeyPair_2eproto_getter() {
  return &descriptor_table_skissm_2fKeyPair_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fKeyPair_2eproto(&descriptor_table_skissm_2fKeyPair_2eproto);
namespace skissm {

// ===================================================================

class KeyPair::_Internal {
 public:
};

KeyPair::KeyPair(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:skissm.KeyPair)
}
KeyPair::KeyPair(const KeyPair& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  public_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    public_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_public_key().empty()) {
    public_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_public_key(), 
      GetArenaForAllocation());
  }
  private_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    private_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_private_key().empty()) {
    private_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_private_key(), 
      GetArenaForAllocation());
  }
  // @@protoc_insertion_point(copy_constructor:skissm.KeyPair)
}

inline void KeyPair::SharedCtor() {
public_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  public_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
private_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  private_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

KeyPair::~KeyPair() {
  // @@protoc_insertion_point(destructor:skissm.KeyPair)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void KeyPair::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  public_key_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  private_key_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void KeyPair::ArenaDtor(void* object) {
  KeyPair* _this = reinterpret_cast< KeyPair* >(object);
  (void)_this;
}
void KeyPair::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void KeyPair::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void KeyPair::Clear() {
// @@protoc_insertion_point(message_clear_start:skissm.KeyPair)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  public_key_.ClearToEmpty();
  private_key_.ClearToEmpty();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* KeyPair::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes public_key = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_public_key();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // bytes private_key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          auto str = _internal_mutable_private_key();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* KeyPair::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:skissm.KeyPair)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes public_key = 1;
  if (!this->_internal_public_key().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_public_key(), target);
  }

  // bytes private_key = 2;
  if (!this->_internal_private_key().empty()) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_private_key(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:skissm.KeyPair)
  return target;
}

size_t KeyPair::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:skissm.KeyPair)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes public_key = 1;
  if (!this->_internal_public_key().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_public_key());
  }

  // bytes private_key = 2;
  if (!this->_internal_private_key().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_private_key());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData KeyPair::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    KeyPair::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*KeyPair::GetClassData() const { return &_class_data_; }

void KeyPair::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to,
                      const ::PROTOBUF_NAMESPACE_ID::Message& from) {
  static_cast<KeyPair *>(to)->MergeFrom(
      static_cast<const KeyPair &>(from));
}


void KeyPair::MergeFrom(const KeyPair& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:skissm.KeyPair)
  GOOGLE_DCHECK_NE(&from, this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_public_key().empty()) {
    _internal_set_public_key(from._internal_public_key());
  }
  if (!from._internal_private_key().empty()) {
    _internal_set_private_key(from._internal_private_key());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void KeyPair::CopyFrom(const KeyPair& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:skissm.KeyPair)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool KeyPair::IsInitialized() const {
  return true;
}

void KeyPair::InternalSwap(KeyPair* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &public_key_, lhs_arena,
      &other->public_key_, rhs_arena
  );
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &private_key_, lhs_arena,
      &other->private_key_, rhs_arena
  );
}

::PROTOBUF_NAMESPACE_ID::Metadata KeyPair::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fKeyPair_2eproto_getter, &descriptor_table_skissm_2fKeyPair_2eproto_once,
      file_level_metadata_skissm_2fKeyPair_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::skissm::KeyPair* Arena::CreateMaybeMessage< ::skissm::KeyPair >(Arena* arena) {
  return Arena::CreateMessageInternal< ::skissm::KeyPair >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>